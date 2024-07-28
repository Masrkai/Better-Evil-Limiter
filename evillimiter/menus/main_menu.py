import time
import socket
import curses
import netaddr
import threading
import collections

from terminaltables import SingleTable
from .menu import CommandMenu
from console.io import IO
from console.chart import BarChart
from console.banner import get_main_banner

import networking.utils as netutils
from networking.host import Host
from networking.limit import Limiter, Direction
from networking.spoof import ARPSpoofer
from networking.scan import HostScanner, ScanIntensity
from networking.monitor import BandwidthMonitor
from networking.watch import HostWatcher

class MainMenu(CommandMenu):
    def __init__(self, version, interface, gateway_ip, gateway_mac, netmask):
        super().__init__()
        self.prompt = '({}Main{}) >>> '.format(IO.Style.BRIGHT, IO.Style.RESET_ALL)
        self.parser.add_subparser('clear', self._clear_handler)

        hosts_parser = self.parser.add_subparser('hosts', self._hosts_handler)
        hosts_parser.add_flag('--force', 'force')

        scan_parser = self.parser.add_subparser('scan', self._scan_handler)
        scan_parser.add_parameterized_flag('--range', 'iprange')
        scan_parser.add_parameterized_flag('--intensity', 'intensity')

        limit_parser = self.parser.add_subparser('limit', self._limit_handler)
        limit_parser.add_parameter('id')
        limit_parser.add_parameter('rate')
        limit_parser.add_flag('--upload', 'upload')
        limit_parser.add_flag('--download', 'download')

        block_parser = self.parser.add_subparser('block', self._block_handler)
        block_parser.add_parameter('id')
        block_parser.add_flag('--upload', 'upload')
        block_parser.add_flag('--download', 'download')

        free_parser = self.parser.add_subparser('free', self._free_handler)
        free_parser.add_parameter('id')

        add_parser = self.parser.add_subparser('add', self._add_handler)
        add_parser.add_parameter('ip')
        add_parser.add_parameterized_flag('--mac', 'mac')

        monitor_parser = self.parser.add_subparser('monitor', self._monitor_handler)
        monitor_parser.add_parameter('id')
        monitor_parser.add_parameterized_flag('--interval', 'interval')

        analyze_parser = self.parser.add_subparser('analyze', self._analyze_handler)
        analyze_parser.add_parameter('id')
        analyze_parser.add_parameterized_flag('--duration', 'duration')

        watch_parser = self.parser.add_subparser('watch', self._watch_handler)
        watch_add_parser = watch_parser.add_subparser('add', self._watch_add_handler)
        watch_add_parser.add_parameter('id')
        watch_remove_parser = watch_parser.add_subparser('remove', self._watch_remove_handler)
        watch_remove_parser.add_parameter('id')
        watch_set_parser = watch_parser.add_subparser('set', self._watch_set_handler)
        watch_set_parser.add_parameter('attribute')
        watch_set_parser.add_parameter('value')

        self.parser.add_subparser('help', self._help_handler)
        self.parser.add_subparser('?', self._help_handler)

        self.parser.add_subparser('quit', self._quit_handler)
        self.parser.add_subparser('exit', self._quit_handler)

        self.version = version
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.netmask = netmask

        self.iprange = list(netaddr.IPNetwork('{}/{}'.format(self.gateway_ip, self.netmask)))

        self.host_scanner = HostScanner(self.interface, self.iprange)
        self.arp_spoofer = ARPSpoofer(self.interface, self.gateway_ip, self.gateway_mac)
        self.limiter = Limiter(self.interface)
        self.bandwidth_monitor = BandwidthMonitor(self.interface, 1)
        self.host_watcher = HostWatcher(self.interface, self.iprange, self._reconnect_callback)

        self.hosts = []
        self.hosts_lock = threading.Lock()

        self._print_help_reminder()

        self.arp_spoofer.start()
        self.bandwidth_monitor.start()
        self.host_watcher.start()

    def interrupt_handler(self, ctrl_c=True):
        if ctrl_c:
            IO.spacer()

        IO.ok('cleaning up... stand by...')

        self.arp_spoofer.stop()
        self.bandwidth_monitor.stop()

        for host in self.hosts:
            self._free_host(host)

    def _scan_handler(self, args):
        if args.iprange:
            iprange = self._parse_iprange(args.iprange)
            if iprange is None:
                IO.error('invalid ip range.')
                return
        else:
            iprange = None

        if args.intensity:
            intensity = self._parse_scan_intensity(args.intensity)
            if intensity is None:
                IO.error('invalid intensity level.')
                return
        else:
            intensity = ScanIntensity.NORMAL

        self.host_scanner.set_intensity(intensity)

        with self.hosts_lock:
            for host in self.hosts:
                self._free_host(host)
            
        IO.spacer()
        hosts = self.host_scanner.scan(iprange)

        self.hosts_lock.acquire()
        self.hosts = hosts
        self.hosts_lock.release()

        IO.ok('{}{}{} hosts discovered.'.format(IO.Fore.LIGHTYELLOW_EX, len(hosts), IO.Style.RESET_ALL))
        IO.spacer()

    def _hosts_handler(self, args):
        table_data = [[
            '{}ID{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
            '{}IP address{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
            '{}MAC address{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
            '{}Hostname{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
            '{}Status{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL)
        ]]
        
        with self.hosts_lock:
            for host in self.hosts:
                table_data.append([
                    '{}{}{}'.format(IO.Fore.LIGHTYELLOW_EX, self._get_host_id(host, lock=False), IO.Style.RESET_ALL),
                    host.ip,
                    host.mac,
                    host.name,
                    self.limiter.pretty_status(host)
                ])

        table = SingleTable(table_data, 'Hosts')

        if not args.force and not table.ok:
            IO.error('table does not fit terminal. resize or decrease font size. you can also force the display (--force).')
            return

        IO.spacer()
        IO.print(table.table)
        IO.spacer()

    def _limit_handler(self, args):
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is None or len(hosts) == 0:
            return

        try:
            from networking.utils import BitRate  # Import here to avoid circular dependency
            rate = BitRate.from_rate_string(args.rate)
        except Exception:
            IO.error('limit rate is invalid.')
            return

        direction = self._parse_direction_args(args)

        for host in hosts:
            self.arp_spoofer.add(host)
            self.limiter.limit(host, direction, rate)
            self.bandwidth_monitor.add(host)

            IO.ok('{}{}{r} {} {}limited{r} to {}.'.format(IO.Fore.LIGHTYELLOW_EX, host.ip, Direction.pretty_direction(direction), IO.Fore.LIGHTRED_EX, rate, r=IO.Style.RESET_ALL))

    def _block_handler(self, args):
        hosts = self._get_hosts_by_ids(args.id)
        direction = self._parse_direction_args(args)

        if hosts is not None and len(hosts) > 0:
            for host in hosts:
                if not host.spoofed:
                    self.arp_spoofer.add(host)

                self.limiter.block(host, direction)
                self.bandwidth_monitor.add(host)
                IO.ok('{}{}{r} {} {}blocked{r}.'.format(IO.Fore.LIGHTYELLOW_EX, host.ip, Direction.pretty_direction(direction), IO.Fore.RED, r=IO.Style.RESET_ALL))

    def _free_handler(self, args):
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is not None and len(hosts) > 0:
            for host in hosts:
                self._free_host(host)

    def _add_handler(self, args):
        ip = args.ip
        if not netutils.validate_ip_address(ip):
            IO.error('invalid ip address.')
            return

        if args.mac:
            mac = args.mac
            if not netutils.validate_mac_address(mac):
                IO.error('invalid mac address.')
                return
        else:
            mac = netutils.get_mac_by_ip(self.interface, ip)
            if mac is None:
                IO.error('unable to resolve mac address. specify manually (--mac).')
                return

        name = None
        try:
            name = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

        host = Host(ip, mac, name)
        IO.ok('{}{}{r} {}added{r} to host list.'.format(IO.Fore.LIGHTYELLOW_EX, host.ip, IO.Fore.GREEN, r=IO.Style.RESET_ALL))
        IO.spacer()

        self.hosts_lock.acquire()
        self.hosts.append(host)
        self.hosts_lock.release()

    def _monitor_handler(self, args):
        interval = None

        if args.interval:
            try:
                interval = int(args.interval)
            except Exception:
                IO.error('invalid interval.')
                return

        hosts = self._get_hosts_by_ids(args.id)

        if hosts is not None and len(hosts) > 0:
            for host in hosts:
                if not host.spoofed:
                    self.arp_spoofer.add(host)

                self.bandwidth_monitor.add(host, interval)
                IO.ok('{}{}{r} is {}being monitored{r}.'.format(IO.Fore.LIGHTYELLOW_EX, host.ip, IO.Fore.GREEN, r=IO.Style.RESET_ALL))

    def _analyze_handler(self, args):
        duration = None

        if args.duration:
            try:
                duration = int(args.duration)
            except Exception:
                IO.error('invalid duration.')
                return

        hosts = self._get_hosts_by_ids(args.id)
        if hosts is not None and len(hosts) > 0:
            IO.spacer()
            for host in hosts:
                result = self.bandwidth_monitor.analyze(host, duration)

                table_data = [['Protocol', 'Upload', 'Download']]
                total_upload = 0
                total_download = 0

                for key, value in result.items():
                    table_data.append([
                        key,
                        BitRate(value['upload']),
                        BitRate(value['download'])
                    ])

                    total_upload += value['upload']
                    total_download += value['download']

                table = SingleTable(table_data, host.ip)
                IO.print(table.table)
                IO.spacer()

                IO.ok('{}total upload:{} {}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL, BitRate(total_upload)))
                IO.ok('{}total download:{} {}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL, BitRate(total_download)))
                IO.spacer()

    def _watch_handler(self, args):
        self.parser.print_subparser_help('watch')

    def _watch_add_handler(self, args):
        hosts = self._get_hosts_by_ids(args.id)

        if hosts is not None and len(hosts) > 0:
            for host in hosts:
                self.host_watcher.add(host)
                IO.ok('{}{}{r} is {}being watched{r}.'.format(IO.Fore.LIGHTYELLOW_EX, host.ip, IO.Fore.GREEN, r=IO.Style.RESET_ALL))

    def _watch_remove_handler(self, args):
        hosts = self._get_hosts_by_ids(args.id)

        if hosts is not None and len(hosts) > 0:
            for host in hosts:
                self.host_watcher.remove(host)
                IO.ok('{}{}{r} is no longer {}being watched{r}.'.format(IO.Fore.LIGHTYELLOW_EX, host.ip, IO.Fore.GREEN, r=IO.Style.RESET_ALL))

    def _watch_set_handler(self, args):
        attribute = args.attribute
        value = args.value

        self.host_watcher.set(attribute, value)
        IO.ok('attribute {}{}{} set to {}{}{}.'.format(IO.Style.BRIGHT, attribute, IO.Style.RESET_ALL, IO.Style.BRIGHT, value, IO.Style.RESET_ALL))

    def _quit_handler(self, args):
        self.interrupt_handler(ctrl_c=False)
        self.stop()

    def _help_handler(self, args):
        self.parser.print_help()

    def _clear_handler(self, args):
        IO.clear()

    def _print_help_reminder(self):
        IO.spacer()
        IO.ok('{}type {}help{} for available commands.'.format(IO.Style.BRIGHT, IO.Fore.LIGHTYELLOW_EX, IO.Style.RESET_ALL))
        IO.spacer()

    def _reconnect_callback(self, host):
        if host.spoofed:
            self.arp_spoofer.add(host)

        self.bandwidth_monitor.add(host)

    def _parse_iprange(self, iprange):
        result = []

        iprange = iprange.split(',')
        for ip in iprange:
            ip = ip.strip()

            try:
                if '-' in ip:
                    ip = ip.split('-')
                    for i in netaddr.IPRange(ip[0], ip[1]):
                        result.append(i)
                else:
                    for i in netaddr.IPNetwork(ip):
                        result.append(i)
            except Exception:
                return None

        return result

    def _parse_scan_intensity(self, intensity):
        if intensity == 'low':
            return ScanIntensity.LOW

        if intensity == 'normal':
            return ScanIntensity.NORMAL

        if intensity == 'high':
            return ScanIntensity.HIGH

        return None

    def _get_hosts_by_ids(self, ids):
        hosts = []
        ids = ids.split(',')
        ids = list(map(str.strip, ids))

        with self.hosts_lock:
            for id in ids:
                for host in self.hosts:
                    if str(self._get_host_id(host, lock=False)) == id:
                        hosts.append(host)

        if len(hosts) == 0:
            IO.error('no matching hosts found.')

        return hosts

    def _get_host_id(self, host, lock=True):
        if lock:
            self.hosts_lock.acquire()

        result = self.hosts.index(host)

        if lock:
            self.hosts_lock.release()

        return result

    def _free_host(self, host):
        if host.spoofed:
            self.arp_spoofer.remove(host)

        self.limiter.free(host)
        self.bandwidth_monitor.remove(host)

        with self.hosts_lock:
            self.hosts.remove(host)

        IO.ok('{}{}{r} {}freed{r}.'.format(IO.Fore.LIGHTYELLOW_EX, host.ip, IO.Fore.RED, r=IO.Style.RESET_ALL))

    def _parse_direction_args(self, args):
        direction = Direction.DOWNLOAD

        if args.upload and args.download:
            direction = Direction.ALL
        elif args.upload:
            direction = Direction.UPLOAD

        return direction
