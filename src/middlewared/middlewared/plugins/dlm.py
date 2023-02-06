import asyncio
import binascii
import contextlib
import ctypes
import glob
import ipaddress
import os
import os.path
import pathlib
import socket

from middlewared.service import Service, private
from middlewared.utils import run


class sockaddr_in(ctypes.Structure):
    _fields_ = [('sa_family', ctypes.c_ushort),  # sin_family
                ('sin_port', ctypes.c_ushort),
                ('sin_addr', ctypes.c_byte * 4),
                ('__pad', ctypes.c_byte * 8)]    # struct sockaddr_in is 16 bytes


def to_sockaddr(address, port=None):
    addr_obj = ipaddress.ip_address(address)
    if addr_obj.version == 4:
        addr = sockaddr_in()
        addr.sa_family = ctypes.c_ushort(socket.AF_INET)
        if port:
            addr.sin_port = ctypes.c_ushort(socket.htons(port))
        if address:
            bytes_ = [int(i) for i in address.split('.')]
            addr.sin_addr = (ctypes.c_byte * 4)(*bytes_)
    else:
        raise NotImplementedError('Not implemented')

    return addr


class KernelDlm(object):
    """
    Simple interface with the kernel dlm.
    """

    SYSFS_DIR = '/sys/kernel/dlm'
    CLUSTER_DIR = '/sys/kernel/config/dlm/cluster'
    SPACES_DIR = CLUSTER_DIR + '/spaces'
    COMMS_DIR = CLUSTER_DIR + '/comms'

    def __init__(self, name):
        with contextlib.suppress(FileExistsError):
            for d in (KernelDlm.CLUSTER_DIR, KernelDlm.SPACES_DIR, KernelDlm.COMMS_DIR):
                os.mkdir(d)
                if d == KernelDlm.CLUSTER_DIR:
                    with open(f'{d}/cluster_name', 'w') as f:
                        f.write(name)
        self.stopped = {}

    def comms_add_node(self, nodeid, addr, local, port=0, mark=None):
        # Create comms directory for this node if necessary
        node_path = os.path.join(KernelDlm.COMMS_DIR, str(nodeid))
        with contextlib.suppress(FileExistsError):
            os.mkdir(node_path)

            # Set the nodeid
            with open(os.path.join(node_path, 'nodeid'), 'w') as f:
                f.write(str(nodeid))

            # Set the address
            sockbytes = bytes(to_sockaddr(addr, port))
            data = sockbytes + bytes(128 - len(sockbytes))
            with open(os.path.join(node_path, 'addr'), 'wb') as f:
                f.write(data)

            # Set skb mark.
            # Added to kernel 5.9 in a5b7ab6352bf ("fs: dlm: set skb mark for listen socket")
            if mark is not None:
                with open(os.path.join(node_path, 'mark'), 'w') as f:
                    f.write(str(mark))

            # Finally set whether local or not
            with open(os.path.join(node_path, 'local'), 'w') as f:
                f.write('1' if local else '0')

    def comms_remove_node(self, nodeid):
        node_path = os.path.join(KernelDlm.COMMS_DIR, str(nodeid))
        with contextlib.suppress(FileNotFoundError):
            os.rmdir(node_path)

    def set_sysfs(self, section, attribute, value):
        with open(os.path.join(KernelDlm.SYSFS_DIR, section, attribute), 'w') as f:
            f.write(str(value))

    def set_sysfs_control(self, lockspace_name, value):
        self.set_sysfs(lockspace_name, 'control', value)

    def set_sysfs_event_done(self, lockspace_name, value):
        self.set_sysfs(lockspace_name, 'event_done', value)

    def set_sysfs_id(self, lockspace_name, value):
        self.set_sysfs(lockspace_name, 'id', value)

    def set_sysfs_nodir(self, lockspace_name, value):
        self.set_sysfs(lockspace_name, 'nodir', value)

    def lockspace_set_global_id(self, lockspace_name):
        self.set_sysfs_id(lockspace_name, binascii.crc32(f'dlm:ls:{lockspace_name}\00'.encode('utf-8')))

    def lockspace_mark_stopped(self, lockspace_name):
        self.stopped[lockspace_name] = True

    def lockspace_is_stopped(self, lockspace_name):
        return self.stopped.get(lockspace_name, False)

    def lockspace_stop(self, lockspace_name):
        if not self.stopped.get(lockspace_name, False):
            self.set_sysfs_control(lockspace_name, 0)
            self.stopped[lockspace_name] = True
            return True
        else:
            return False

    def lockspace_start(self, lockspace_name):
        if self.stopped.get(lockspace_name, False):
            self.set_sysfs_control(lockspace_name, 1)
            self.stopped[lockspace_name] = False
            return True
        else:
            return False

    def lockspace_add_node(self, lockspace_name, nodeid, weight=None):
        """
        Add the specified node to the lockspace
        """
        spaces_path = os.path.join(KernelDlm.SPACES_DIR, lockspace_name)
        with contextlib.suppress(FileExistsError):
            os.mkdir(spaces_path)
        # Check to see if we already have the directory, and remove it if so
        # so dlm-kernel can notice they've left and rejoined.
        node_path = os.path.join(spaces_path, 'nodes', '%d' % nodeid)
        with contextlib.suppress(FileNotFoundError):
            os.rmdir(node_path)
        with contextlib.suppress(FileExistsError):
            os.mkdir(node_path)
            with open(os.path.join(node_path, 'nodeid'), 'w') as f:
                f.write(str(nodeid))
            if weight is not None:
                with open(os.path.join(node_path, 'weight'), 'w') as f:
                    f.write(str(weight))

    def lockspace_remove_node(self, lockspace_name, nodeid):
        """
        Remove the specified nodeid from the lockspace.
        """
        node_path = os.path.join(KernelDlm.SPACES_DIR, lockspace_name, 'nodes', '%d' % nodeid)
        with contextlib.suppress(FileNotFoundError):
            os.rmdir(node_path)

    def lockspace_leave(self, lockspace_name):
        """
        Current node is leaving the lockspace.

        Remove all nodes and delete the lockspace.
        """
        spaces_path = os.path.join(KernelDlm.SPACES_DIR, lockspace_name)
        with contextlib.suppress(FileNotFoundError):
            for d in glob.glob(os.path.join(spaces_path, 'nodes', '*')):
                os.rmdir(d)
            os.rmdir(spaces_path)
        if lockspace_name in self.stopped:
            del self.stopped[lockspace_name]

    def destroy(self):
        with contextlib.suppress(FileNotFoundError):
            for dirname in glob.glob(os.path.join(KernelDlm.COMMS_DIR, '*')):
                os.rmdir(dirname)
            for dirname in glob.glob(os.path.join(KernelDlm.SPACES_DIR, '*')):
                os.rmdir(dirname)
            os.rmdir(KernelDlm.CLUSTER_DIR)

    def node_lockspaces(self, nodeid):
        """
        Return an iterator that will yield the names of the lockspaces that contain
        the specified nodeid.
        """
        p = pathlib.Path(KernelDlm.SPACES_DIR)
        for lsnp in p.glob(f'*/nodes/{nodeid}'):
            yield lsnp.parts[-3]


class DistributedLockManager(Service):
    """
    Support the configuration of the kernel dlm in a multi-controller environment.

    This will handle the following events:
    - kernel udev online lockspace event (aka dlm.join_lockspace)
    - kernel udev offline lockspace event (aka dlm.leave_lockspace)
    - node join event (from another controller)
    - node leave event (from another controller)
    """

    class Config:
        private = True
        namespace = 'dlm'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.kernel_dlm = None
        # The nodeID & nodes will be initialized by setup_nodes
        self.nodeID = 0
        self.nodes = {}

    @private
    async def setup_nodes(self):
        """
        Setup the self.nodes dict and the self.nodeID.

        It makes no guarantees that the remote node is currently accessible.
        """
        if await self.middleware.call('failover.licensed'):
            self.node = await self.middleware.call('failover.node')
            self.nodes[1] = {'ip': '169.254.10.1', 'local': self.node == 'A'}
            self.nodes[2] = {'ip': '169.254.10.2', 'local': self.node == 'B'}

        for nodeid, node in self.nodes.items():
            if node['local']:
                self.nodeID = nodeid

    @private
    async def create(self):
        if not self.nodes:
            await self.middleware.call('dlm.setup_nodes')
        # For code robustness sake, ensure the dlm is loaded.  Should not be necessary.
        if not os.path.isdir(KernelDlm.SYSFS_DIR):
            self.logger.warn('Loading kernel dlm')
            cp = await run(['modprobe', 'dlm'], check=False)
            if cp.returncode:
                self.logger.error('Failed to load dlm kernel module with %r error', cp.stderr.decode())
        # Setup the kernel dlm static config (i.e. define nodes, but not lockspaces)
        k = KernelDlm('HA')
        for nodeid, node in self.nodes.items():
            if node['local']:
                k.comms_add_node(nodeid, node['ip'], node['local'])
            elif await self.middleware.call('failover.remote_connected'):
                k.comms_add_node(nodeid, node['ip'], node['local'])
        self.kernel_dlm = k

    @private
    async def stop_kernel_lockspace(self, dest_nodeid, lockspace_name):
        if dest_nodeid == self.nodeID:
            # Local operation
            self.logger.debug('[LOCAL] Stopping kernel lockspace %s on node %d', lockspace_name, dest_nodeid)

            if self.kernel_dlm.lockspace_stop(lockspace_name):
                self.logger.debug('Stopped lockspace %s', lockspace_name)

        elif await self.middleware.call('failover.remote_connected'):
            # Remote operation
            self.logger.debug('[REMOTE] Stopping kernel lockspace %s on node %d', lockspace_name, dest_nodeid)
            await self.middleware.call(
                'failover.call_remote', 'dlm.stop_kernel_lockspace', [dest_nodeid, lockspace_name], {'timeout': 5}
            )

    @private
    async def start_kernel_lockspace(self, dest_nodeid, lockspace_name):
        if dest_nodeid == self.nodeID:
            # Local operation
            self.logger.debug('[LOCAL] Starting kernel lockspace %s on node %d', lockspace_name, dest_nodeid)

            # If already stopped, tell the kernel lockspace to start
            if self.kernel_dlm.lockspace_start(lockspace_name):
                self.logger.debug('Started lockspace %s', lockspace_name)

        elif await self.middleware.call('failover.remote_connected'):
            # Remote operation
            self.logger.debug('[REMOTE] Starting kernel lockspace %s on node %d', lockspace_name, dest_nodeid)
            await self.middleware.call(
                'failover.call_remote', 'dlm.start_kernel_lockspace', [dest_nodeid, lockspace_name], {'timeout': 5}
            )

    @private
    async def join_kernel_lockspace(self, dest_nodeid, lockspace_name, joining_nodeid):
        if dest_nodeid == self.nodeID:
            # Local operation
            self.logger.debug('[LOCAL] Joining kernel lockspace %s for node %s on node %s', lockspace_name, joining_nodeid, dest_nodeid)

            # Ensure kernel lockspace is stopped
            if not self.kernel_dlm.lockspace_is_stopped(lockspace_name):
                self.logger.warn('Lockspace %s not stopped', lockspace_name)
                return

            # If joining set global id
            if dest_nodeid == joining_nodeid:
                self.logger.debug('Setting global id for lockspace %s', lockspace_name)
                self.kernel_dlm.lockspace_set_global_id(lockspace_name)

            # Set members
            self.logger.debug('Adding node to lockspace %s', lockspace_name)
            self.kernel_dlm.lockspace_add_node(lockspace_name, joining_nodeid)

            # Start kernel lockspace again.
            if self.kernel_dlm.lockspace_start(lockspace_name):
                self.logger.debug('Started lockspace %s', lockspace_name)

            # If joining set event_done 0
            if dest_nodeid == joining_nodeid:
                self.logger.debug('Event done lockspace %s', lockspace_name)
                self.kernel_dlm.set_sysfs_event_done(lockspace_name, 0)

        elif await self.middleware.call('failover.remote_connected'):
            # Remote operation
            self.logger.debug('[REMOTE] Joining kernel lockspace %s for node %s on node %s', lockspace_name, joining_nodeid, dest_nodeid)
            await self.middleware.call(
                'failover.call_remote', 'dlm.join_kernel_lockspace', [dest_nodeid, lockspace_name, joining_nodeid], {'timeout': 5}
            )

    @private
    async def leave_kernel_lockspace(self, dest_nodeid, lockspace_name, leaving_nodeid):
        if dest_nodeid == self.nodeID:
            # Local operation
            self.logger.debug('[LOCAL] Leaving kernel lockspace %s', lockspace_name)

            # Are we the ones leaving?
            if dest_nodeid == leaving_nodeid:
                # Remove members
                self.logger.debug('Leaving lockspace %s', lockspace_name)
                self.kernel_dlm.lockspace_leave(lockspace_name)
                # Event done
                self.logger.debug('Event done lockspace %s', lockspace_name)
                self.kernel_dlm.set_sysfs_event_done(lockspace_name, 0)
                return

            # Make config changes
            self.logger.debug('Removing node from lockspace %s', lockspace_name)
            self.kernel_dlm.lockspace_remove_node(lockspace_name, leaving_nodeid)

        elif await self.middleware.call('failover.remote_connected'):
            # Remote operation
            self.logger.debug('[REMOTE] Leaving kernel lockspace %s', lockspace_name)
            await self.middleware.call(
                'failover.call_remote', 'dlm.leave_kernel_lockspace', [dest_nodeid, lockspace_name, leaving_nodeid], {'timeout': 5}
            )

    @private
    async def join_lockspace(self, lockspace_name):
        self.logger.info('Joining lockspace %s', lockspace_name)
        if not self.nodes:
            await self.middleware.call('dlm.setup_nodes')
        if not self.kernel_dlm:
            await self.middleware.call('dlm.create')
        try:
            # Note that by virtue of this being a join_lockspace kernel lockspace stopped is already True (on this node)
            self.kernel_dlm.lockspace_mark_stopped(lockspace_name)

            # Stop kernel lockspace (on all nodes)
            await asyncio.gather(*[self.stop_kernel_lockspace(nodeid, lockspace_name) for nodeid in self.nodes])

            # Join the kernel lockspace (on all nodes)
            await asyncio.gather(*[self.join_kernel_lockspace(nodeid, lockspace_name, self.nodeID) for nodeid in self.nodes])
        except Exception:
            self.logger.error('Failed to join lockspace %s', lockspace_name, exc_info=True)
            self.kernel_dlm.set_sysfs_event_done(lockspace_name, 1)

    @private
    async def leave_lockspace(self, lockspace_name):
        self.logger.info('Leaving lockspace %s', lockspace_name)
        if not self.nodes:
            await self.middleware.call('dlm.setup_nodes')
        if not self.kernel_dlm:
            await self.middleware.call('dlm.create')
        try:
            # Stop kernel lockspace (on all nodes)
            await asyncio.gather(*[self.stop_kernel_lockspace(nodeid, lockspace_name) for nodeid in self.nodes])

            # Leave the kernel lockspace (on all nodes).
            await asyncio.gather(*[self.leave_kernel_lockspace(nodeid, lockspace_name, self.nodeID) for nodeid in self.nodes])

            # Start the kernel lockspace on remaining nodes
            await asyncio.gather(*[self.stop_kernel_lockspace(nodeid, lockspace_name) for nodeid in self.nodes if nodeid != self.nodeID])

        except Exception:
            self.logger.error('Failed to leave lockspace %s', lockspace_name, exc_info=True)
            if self.kernel_dlm.lockspace_start(lockspace_name):
                self.logger.debug('Started lockspace %s', lockspace_name)
            self.kernel_dlm.set_sysfs_event_done(lockspace_name, 1)

    @private
    async def add_node(self, nodeid):
        # if await self.middleware.call('failover.remote_connected'):
        node = self.nodes.get(nodeid)
        if node:
            self.kernel_dlm.comms_add_node(nodeid, node['ip'], node['local'])

    @private
    async def remove_node(self, nodeid):
        """
        Handle a node failure.
        """
        node = self.nodes.get(nodeid)
        if node:
            # Anticipate the day when we have N nodes, but for now this equates to this node.
            active_node_ids = set(self.nodes) - set([nodeid])
            # Remove the node from any lockspaces it is in
            for lockspace_name in self.kernel_dlm.node_lockspaces(nodeid):
                await asyncio.gather(*[self.stop_kernel_lockspace(node_id, lockspace_name) for node_id in active_node_ids])
                await asyncio.gather(*[self.leave_kernel_lockspace(node_id, lockspace_name, nodeid) for node_id in active_node_ids])
                await asyncio.gather(*[self.start_kernel_lockspace(node_id, lockspace_name) for node_id in active_node_ids])

            self.kernel_dlm.comms_remove_node(nodeid)


async def udev_dlm_hook(middleware, data):
    """
    This hook is called on udevd dlm type events.  It's purpose is to
    allow configuration of dlm lockspaces by handling 'online' and
    'offline' events.

    At the moment this should only be used in HA systems with ALUA enabled
    for iSCSI targets, but there are aspects that are generic and can
    be implemented even if this was not the configuration.
    """
    if data.get('SUBSYSTEM') != 'dlm' or data.get('ACTION') not in ['online', 'offline']:
        return

    lockspace = data.get('LOCKSPACE')
    if lockspace is None:
        middleware.logger.error('Missing lockspace name', exc_info=True)
        return

    if data['ACTION'] == 'online':
        await middleware.call('dlm.join_lockspace', lockspace)
    elif data['ACTION'] == 'offline':
        await middleware.call('dlm.leave_lockspace', lockspace)


# def remote_status_event(middleware, *args, **kwargs):
#    middleware.call_sync('dlm.status_refresh')

async def setup(middleware):
    middleware.register_hook('udev.dlm', udev_dlm_hook)
    # await middleware.call('failover.remote_on_connect', remote_status_event)
    # await middleware.call('failover.remote_on_disconnect', remote_status_event)
