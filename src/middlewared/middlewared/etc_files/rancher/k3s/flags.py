import contextlib
import ipaddress
import json
import os
import shutil
import yaml


FLAGS_PATH = '/etc/rancher/k3s/config.yaml'


def render(service, middleware):
    shutil.rmtree('/etc/cni/net.d', ignore_errors=True)
    config = middleware.call_sync('kubernetes.config')
    if not config['pool']:
        with contextlib.suppress(OSError):
            os.unlink(FLAGS_PATH)
        return

    kube_controller_args = [
        'terminated-pod-gc-threshold=5',
    ]

    for cluster_cidr in config["cluster_cidr"][:2]:
        ip_network = ipaddress.ip_network(cluster_cidr)
        if type(ip_network) is ipaddress.IPv4Network:
            kube_controller_args.append(
                f'node-cidr-mask-size-ipv4={ip_network.prefixlen}'
            )
        elif type(ip_network) is ipaddress.IPv6Network:
            kube_controller_args.append(
                f'node-cidr-mask-size-ipv6={ip_network.prefixlen}'
            )
            
    kube_api_server_args = [
        'service-node-port-range=9000-65535',
        'enable-admission-plugins=NodeRestriction,NamespaceLifecycle,ServiceAccount',
        'audit-log-path=/var/log/k3s_server_audit.log',
        'audit-log-maxage=30',
        'audit-log-maxbackup=10',
        'audit-log-maxsize=100',
        'service-account-lookup=true',
        'feature-gates=MixedProtocolLBService=true',
    ]
    kubelet_args = [
        'max-pods=250',
    ]
    os.makedirs('/etc/rancher/k3s', exist_ok=True)

    features_mapping = {'servicelb': 'servicelb', 'metrics_server': 'metrics-server'}

    with open(FLAGS_PATH, 'w') as f:
        f.write(yaml.dump({
            'cluster-cidr': ",".join(config['cluster_cidr']),
            'service-cidr': ",".join(config['service_cidr']),
            'cluster-dns': config['cluster_dns_ip'],
            'data-dir': os.path.join('/mnt', config['dataset'], 'k3s'),
            'node-ip': ",".join(config['node_ip']),
            'node-external-ip': ','.join([
                interface['address'] for interface in middleware.call_sync('interface.ip_in_use', {'ipv6': False})
            ]),
            'kube-controller-manager-arg': kube_controller_args,
            'kube-apiserver-arg': kube_api_server_args,
            'kubelet-arg': kubelet_args,
            'protect-kernel-defaults': True,
            'disable': [features_mapping[feature] for feature in features_mapping if not config[feature]],
            'flannel-backend': 'host-gw',
            'flannel-ipv6-masq': True,
        }))

    with open('/etc/containerd.json', 'w') as f:
        f.write(json.dumps({
            'verifyVolumes': config['validate_host_path'],
            'appsDataset': config['dataset'],
        }))
