[global]
        run as user = netdata
        web files owner = root
        web files group = root
        # Netdata is not designed to be exposed to potentially hostile
        # networks. See https://github.com/netdata/netdata/issues/164
        bind socket to IP = 0.0.0.0

[plugins]
	proc = yes
        diskspace = no
        cgroups = no
        tc = no
        idlejitter = no
        perf = no
        apps = no
        nfacct = no

[web]
	enabled = no

[health]
	enabled = no

[statsd]
	enabled = no

[plugin:proc]
	netdata server resources = yes
	/proc/diskstats = yes
	/proc/meminfo = yes
	/proc/net/dev = yes
	/proc/pagetypeinfo = no
	/proc/stat = no
	/proc/uptime = no
	/proc/loadavg = no
	/proc/sys/kernel/random/entropy_avail = no
	/proc/pressure = no
	/proc/interrupts = no
	/proc/softirqs = no
	/proc/vmstat = no
	/sys/kernel/mm/ksm = no
	/sys/block/zram = no
	/sys/devices/system/edac/mc = no
	/sys/devices/system/node = no
	/proc/net/wireless = no
	/proc/net/sockstat = no
	/proc/net/sockstat6 = no
	/proc/net/netstat = no
	/proc/net/snmp = no
	/proc/net/snmp6 = no
	/proc/net/sctp/snmp = no
	/proc/net/softnet_stat = no
	/proc/net/ip_vs/stats = no
	/sys/class/infiniband = no
	/proc/net/stat/conntrack = no
	/proc/net/stat/synproxy = no
	/proc/mdstat = no
	/proc/net/rpc/nfsd = no
	/proc/net/rpc/nfs = no
	/proc/spl/kstat/zfs/arcstats = no
	/sys/fs/btrfs = no
	ipc = no
	/sys/class/power_supply = no

[plugin:proc:/proc/net/dev]
	filename to monitor = /proc/net/dev
	path to get virtual interfaces = /sys/devices/virtual/net/%s
	path to get net device speed = /sys/class/net/%s/speed
	path to get net device duplex = /sys/class/net/%s/duplex
	path to get net device operstate = /sys/class/net/%s/operstate
	enable new interfaces detected at runtime = auto
	bandwidth for all interfaces = auto
	packets for all interfaces = auto
	errors for all interfaces = auto
	drops for all interfaces = auto
	fifo for all interfaces = no
	compressed packets for all interfaces = auto
	frames, collisions, carrier counters for all interfaces = auto
	disable by default interfaces matching = lo fireqos* *-ifb kube-* veth*
	refresh interface speed every seconds = 1
	refresh interface duplex every seconds = 1
	refresh interface operstate every seconds = 1

[plugin:proc:/proc/diskstats]
	enable new disks detected at runtime = yes
	performance metrics for physical disks = yes
	performance metrics for virtual disks = no
	performance metrics for partitions = no
	bandwidth for all disks = auto
	operations for all disks = auto
	merged operations for all disks = auto
	i/o time for all disks = auto
	queued operations for all disks = auto
	utilization percentage for all disks = auto
	backlog for all disks = auto
	bcache for all disks = no
	bcache priority stats update every = 0
	remove charts of removed disks = yes
	path to get block device = /sys/block/%s
	# path to get block device bcache = /sys/block/%s/bcache
	# path to get virtual block device = /sys/devices/virtual/block/%s
	path to get block device infos = /sys/dev/block/%lu:%lu/%s
	# path to device mapper = /dev/mapper
	path to /dev/disk/by-label = /dev/disk/by-label
	path to /dev/disk/by-id = /dev/disk/by-id
	# path to /dev/vx/dsk = /dev/vx/dsk
	name disks by id = no
	preferred disk ids = *
	exclude disks = loop* ram* zd* md* dm*
	filename to monitor = /proc/diskstats
	performance metrics for disks with major 259 = yes
	performance metrics for disks with major 8 = yes
	performance metrics for disks with major 65 = yes
	performance metrics for disks with major 9 = no
	performance metrics for disks with major 253 = no
	performance metrics for disks with major 230 = no