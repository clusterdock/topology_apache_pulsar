# -*- coding: utf-8 -*-
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import os
import textwrap

from javaproperties import PropertiesFile

from clusterdock.models import Cluster, Node
from clusterdock.utils import wait_for_condition

DEFAULT_NAMESPACE = 'clusterdock'

BROKER_SERVICE_PORT = 6650
BROKER_SERVICE_TLS_PORT = 6651
WEB_SERVICE_PORT = 8080
WEB_SERVICE_TLS_PORT = 8443

PULSAR_HOME = '/opt/pulsar'

BOOKKEEPER_CONF = '{}/conf/bookkeeper.conf'.format(PULSAR_HOME)
BROKER_CONF = '{}/conf/broker.conf'.format(PULSAR_HOME)
CLIENT_CONF = '{}/conf/client.conf'.format(PULSAR_HOME)
PROXY_CONF = '{}/conf/proxy.conf'.format(PULSAR_HOME)
ZOOKEEPER_CONF = '{}/conf/zookeeper.conf'.format(PULSAR_HOME)

# Files placed in this directory on a node are available
# in clusterdock_config_directory after Pulsar is started.
# Also, this gets volume mounted to all other nodes and hence available there too.
CLUSTERDOCK_CLIENT_CONTAINER_DIR = '/etc/clusterdock'

TLS_CONF_URL = 'https://pulsar.incubator.apache.org/docs/latest/security/openssl.cnf'
TLS_DIR = '{}/pulsar_tls'.format(CLUSTERDOCK_CLIENT_CONTAINER_DIR)
TLS_CLIENT_DIR = '{}/client'.format(TLS_DIR)

logger = logging.getLogger('clusterdock.{}'.format(__name__))


def main(args):
    quiet = not args.verbose

    node_image = '{}/{}/topology_apache_pulsar:pulsar-{}'.format(args.registry,
                                                                 args.namespace or DEFAULT_NAMESPACE,
                                                                 args.pulsar_version)
    ports = [{WEB_SERVICE_PORT: WEB_SERVICE_PORT} if args.predictable else WEB_SERVICE_PORT,
             {WEB_SERVICE_TLS_PORT: WEB_SERVICE_TLS_PORT} if args.predictable else WEB_SERVICE_TLS_PORT,
             {BROKER_SERVICE_PORT: BROKER_SERVICE_PORT} if args.predictable else BROKER_SERVICE_PORT,
             {BROKER_SERVICE_TLS_PORT: BROKER_SERVICE_TLS_PORT} if args.predictable else BROKER_SERVICE_TLS_PORT]

    clusterdock_config_host_dir = os.path.realpath(os.path.expanduser(args.clusterdock_config_directory))
    volumes = [{clusterdock_config_host_dir: CLUSTERDOCK_CLIENT_CONTAINER_DIR}]

    proxy_node = Node(hostname=args.proxy_node_name,
                      group='proxy',
                      image=node_image,
                      ports=ports,
                      volumes=volumes)
    broker_nodes = [Node(hostname=hostname, group='broker', image=node_image, volumes=volumes)
                    for hostname in args.broker_nodes]
    zk_nodes = [Node(hostname=hostname, group='zookeeper', image=node_image, volumes=volumes)
                for hostname in args.zookeeper_nodes]
    nodes = [proxy_node] + broker_nodes + zk_nodes
    cluster = Cluster(*nodes)
    cluster.start(args.network)

    logger.info('Starting pulsar cluster (%s) version %s ...', args.pulsar_cluster_name, args.pulsar_version)

    # zookeeper
    for idx, node in enumerate(zk_nodes, start=1):
        zookeeper_conf = node.get_file(ZOOKEEPER_CONF)
        zookeeper_properties = PropertiesFile.loads(zookeeper_conf)
        for srvidx, srvnode in enumerate(zk_nodes, start=1):
            zookeeper_properties['server.{}'.format(srvidx)] = '{}.{}:2888:3888'.format(srvnode.hostname,
                                                                                        cluster.network)
        node.put_file(ZOOKEEPER_CONF, PropertiesFile.dumps(zookeeper_properties))
        zookeeper_commands = [
            'mkdir -p {}/data/zookeeper'.format(PULSAR_HOME),
            'echo {} > {}/data/zookeeper/myid'.format(idx, PULSAR_HOME),
            '{}/bin/pulsar-daemon start zookeeper'.format(PULSAR_HOME)
        ]
        execute_node_command(node, ' && '.join(zookeeper_commands), quiet, 'Zookeeper start failed')

    web_service_url = 'http://{}.{}:{}'.format(proxy_node.hostname, cluster.network, WEB_SERVICE_PORT)
    web_service_url_tls = 'https://{}.{}:{}'.format(proxy_node.hostname, cluster.network, WEB_SERVICE_TLS_PORT)
    broker_service_url = 'pulsar://{}.{}:{}'.format(proxy_node.hostname, cluster.network, BROKER_SERVICE_PORT)
    broker_service_url_tls = 'pulsar+ssl://{}.{}:{}'.format(proxy_node.hostname, cluster.network,
                                                            BROKER_SERVICE_TLS_PORT)

    init_cluster_cmd = ('{home}/bin/pulsar initialize-cluster-metadata'
                        ' --cluster {cluster_name}'
                        ' --zookeeper {zkhostname}.{network}:2181'
                        ' --configuration-store {zkhostname}.{network}:2181'
                        ' --web-service-url {web_service_url}'
                        ' --web-service-url-tls {web_service_url_tls}'
                        ' --broker-service-url {broker_service_url}'
                        ' --broker-service-url-tls {broker_service_url_tls}'
                        .format(home=PULSAR_HOME,
                                cluster_name=args.pulsar_cluster_name,
                                zkhostname=zk_nodes[0].hostname,
                                hostname=proxy_node.hostname,
                                network=cluster.network,
                                web_service_url=web_service_url,
                                web_service_url_tls=web_service_url_tls,
                                broker_service_url=broker_service_url,
                                broker_service_url_tls=broker_service_url_tls))
    execute_node_command(zk_nodes[0], init_cluster_cmd, quiet, 'Cluster initialization failed')

    zk_servers_conf = ','.join(['{}.{}:2181'.format(node.hostname, cluster.network) for node in zk_nodes])

    # bookkeepers
    for node in broker_nodes:
        bookkeeper_conf = node.get_file(BOOKKEEPER_CONF)
        bookkeeper_properties = PropertiesFile.loads(bookkeeper_conf)
        bookkeeper_properties['zkServers'] = zk_servers_conf
        node.put_file(BOOKKEEPER_CONF, PropertiesFile.dumps(bookkeeper_properties))

        execute_node_command(node, '{}/bin/pulsar-daemon start bookie'.format(PULSAR_HOME), quiet,
                             'Bookkeeper start failed')
        execute_node_command(node, '{}/bin/bookkeeper shell bookiesanity'.format(PULSAR_HOME), quiet,
                             'Book keeper sanity check failed')

    # brokers
    for node in broker_nodes:
        broker_conf = node.get_file(BROKER_CONF)
        broker_properties = PropertiesFile.loads(broker_conf)
        broker_properties.update({'zookeeperServers': zk_servers_conf,
                                  'configurationStoreServers': zk_servers_conf,
                                  'clusterName': args.pulsar_cluster_name})
        node.put_file(BROKER_CONF, PropertiesFile.dumps(broker_properties))

    # proxy
    proxy_conf = proxy_node.get_file(PROXY_CONF)
    proxy_properties = PropertiesFile.loads(proxy_conf)
    proxy_properties.update({'zookeeperServers': zk_servers_conf,
                             'configurationStoreServers': zk_servers_conf})
    proxy_node.put_file(PROXY_CONF, PropertiesFile.dumps(proxy_properties))

    # TLS
    execute_node_command(proxy_node, 'rm -rf {}'.format(TLS_DIR), quiet=quiet)
    if args.tls:
        setup_commands = [
            'mkdir -p {}'.format(TLS_CLIENT_DIR),
            'wget -P {} {}'.format(TLS_DIR, TLS_CONF_URL),
            'mkdir -p {dir}/certs {dir}/crl {dir}/newcerts {dir}/private'.format(dir=TLS_DIR),
            'chmod 700 {}/private'.format(TLS_DIR),
            'touch {}/index.txt'.format(TLS_DIR),
            'echo "unique_subject = no" > {}/index.txt.attr'.format(TLS_DIR),
            'echo 1000 > {}/serial'.format(TLS_DIR),
        ]
        execute_node_command(proxy_node, ' && '.join(setup_commands), quiet, 'TLS system setup failed')

        ca_auth_commands = [
            'export CA_HOME={}'.format(TLS_DIR),
            'openssl genrsa -out {dir}/private/ca.key.pem 4096'.format(dir=TLS_DIR),
            'chmod 400 {}/private/ca.key.pem'.format(TLS_DIR),
            ('openssl req -config {dir}/openssl.cnf -key {dir}/private/ca.key.pem'
             ' -new -x509 -days 7300 -sha256 -extensions v3_ca -out {dir}/certs/ca.cert.pem'
             ' -subj "/C=US/ST=California/L=Palo Alto/O=My company/CN=*"').format(dir=TLS_DIR),
            'chmod 444 {}/certs/ca.cert.pem'.format(TLS_DIR),
            'cp {}/certs/ca.cert.pem {}'.format(TLS_DIR, TLS_CLIENT_DIR)
        ]
        execute_node_command(proxy_node, ' && '.join(ca_auth_commands), quiet,
                             'Certificate authority creation failed')

        server_cert_commands = [
            'export CA_HOME={}'.format(TLS_DIR),
            'openssl genrsa -out {}/broker.key.pem 2048'.format(TLS_DIR),
            ('openssl pkcs8 -topk8 -inform PEM -outform PEM -in {dir}/broker.key.pem'
             ' -out {dir}/broker.key-pk8.pem -nocrypt').format(dir=TLS_DIR),
            # comman name (CN) needs to be *.<nw> so as that <nw> hosts can access Pulsar cluster
            ('openssl req -config {dir}/openssl.cnf -key {dir}/broker.key.pem -new -sha256 -out {dir}/broker.csr.pem'
             ' -subj "/C=US/ST=California/L=Palo Alto/O=My company/CN=*.{nw}"').format(dir=TLS_DIR, nw=cluster.network),
            ('openssl ca -batch -config {dir}/openssl.cnf -extensions server_cert -days 1000 -notext -md sha256'
             ' -in {dir}/broker.csr.pem -out {dir}/broker.cert.pem').format(dir=TLS_DIR)
        ]
        execute_node_command(proxy_node, ' && '.join(server_cert_commands), quiet,
                             'Broker certificate creation failed')

        for node in broker_nodes:
            broker_conf = node.get_file(BROKER_CONF)
            broker_properties = PropertiesFile.loads(broker_conf)
            broker_properties.update({'tlsEnabled': 'true',
                                      'tlsCertificateFilePath': '{}/broker.cert.pem'.format(TLS_DIR),
                                      'tlsKeyFilePath': '{}/broker.key-pk8.pem'.format(TLS_DIR),
                                      'tlsTrustCertsFilePath': '{}/certs/ca.cert.pem'.format(TLS_DIR)})
            node.put_file(BROKER_CONF, PropertiesFile.dumps(broker_properties))

        proxy_conf = proxy_node.get_file(PROXY_CONF)
        proxy_properties = PropertiesFile.loads(proxy_conf)
        proxy_properties.update({'tlsEnabledInProxy': 'true',
                                 'tlsCertificateFilePath': '{}/broker.cert.pem'.format(TLS_DIR),
                                 'tlsKeyFilePath': '{}/broker.key-pk8.pem'.format(TLS_DIR),
                                 'tlsTrustCertsFilePath': '{}/certs/ca.cert.pem'.format(TLS_DIR),
                                 'tlsEnabledWithBroker': 'true',
                                 'brokerClientTrustCertsFilePath': '{}/certs/ca.cert.pem'.format(TLS_DIR)})
        proxy_node.put_file(PROXY_CONF, PropertiesFile.dumps(proxy_properties))

        for node in nodes:
            client_conf = node.get_file(CLIENT_CONF)
            client_properties = PropertiesFile.loads(client_conf)
            client_properties.update({'webServiceUrl': web_service_url_tls,
                                      'brokerServiceUrl': broker_service_url_tls,
                                      'useTls': 'true',
                                      'tlsAllowInsecureConnection': 'false',
                                      'tlsTrustCertsFilePath': '{}/certs/ca.cert.pem'.format(TLS_DIR)})
            node.put_file(CLIENT_CONF, PropertiesFile.dumps(client_properties))

        # TLS auth
        if args.tls == 'authentication':
            client_cert_commands = [
                'export CA_HOME={}'.format(TLS_DIR),
                'openssl genrsa -out {}/admin.key.pem 2048'.format(TLS_DIR),
                ('openssl pkcs8 -topk8 -inform PEM -outform PEM -in {dir}/admin.key.pem'
                 ' -out {dir}/admin.key-pk8.pem -nocrypt').format(dir=TLS_DIR),
                # comman name (CN) needs to be admin - same as user principal in Pulsar
                ('openssl req -config {dir}/openssl.cnf -key {dir}/admin.key.pem -new -sha256 -out {dir}/admin.csr.pem'
                 ' -subj "/C=US/ST=California/L=Palo Alto/O=My company/CN=admin"').format(dir=TLS_DIR),
                ('openssl ca -batch -config {dir}/openssl.cnf -extensions usr_cert -days 1000 -notext -md sha256'
                 ' -in {dir}/admin.csr.pem -out {dir}/admin.cert.pem').format(dir=TLS_DIR),
                'mv {}/admin.* {}'.format(TLS_DIR, TLS_CLIENT_DIR)
            ]
            execute_node_command(proxy_node, ' && '.join(client_cert_commands), quiet,
                                 'Client certificate creation failed')

            proxy_cert_commands = [
                'export CA_HOME={}'.format(TLS_DIR),
                'openssl genrsa -out {}/proxy.key.pem 2048'.format(TLS_DIR),
                ('openssl pkcs8 -topk8 -inform PEM -outform PEM -in {dir}/proxy.key.pem'
                 ' -out {dir}/proxy.key-pk8.pem -nocrypt').format(dir=TLS_DIR),
                # comman name (CN) needs to be proxyadmin - same as proxy principal in Pulsar
                ('openssl req -config {dir}/openssl.cnf -key {dir}/proxy.key.pem -new -sha256 -out {dir}/proxy.csr.pem'
                 ' -subj "/C=US/ST=California/L=Palo Alto/O=My company/CN=proxyadmin"').format(dir=TLS_DIR),
                ('openssl ca -batch -config {dir}/openssl.cnf -extensions usr_cert -days 1000 -notext -md sha256'
                 ' -in {dir}/proxy.csr.pem -out {dir}/proxy.cert.pem').format(dir=TLS_DIR)
            ]
            execute_node_command(proxy_node, ' && '.join(proxy_cert_commands), quiet,
                                 'Proxy certificate creation failed')

            for node in broker_nodes:
                broker_conf = node.get_file(BROKER_CONF)
                broker_properties = PropertiesFile.loads(broker_conf)
                broker_properties.update({
                    'authenticationEnabled': 'true',
                    'authenticationProviders': 'org.apache.pulsar.broker.authentication.AuthenticationProviderTls',
                    'proxyRoles': 'proxyadmin',
                    'superUserRoles': 'proxyadmin,admin'})
                node.put_file(BROKER_CONF, PropertiesFile.dumps(broker_properties))

            proxy_conf = proxy_node.get_file(PROXY_CONF)
            proxy_properties = PropertiesFile.loads(proxy_conf)
            proxy_properties.update({
                'authenticationEnabled': 'true',
                'authenticationProviders': 'org.apache.pulsar.broker.authentication.AuthenticationProviderTls',
                'brokerClientAuthenticationPlugin': 'org.apache.pulsar.client.impl.auth.AuthenticationTls',
                'brokerClientAuthenticationParameters': ('tlsCertFile:{dir}/proxy.cert.pem,'
                                                         'tlsKeyFile:{dir}/proxy.key-pk8.pem').format(dir=TLS_DIR),
                'superUserRoles': 'admin'})
            proxy_node.put_file(PROXY_CONF, PropertiesFile.dumps(proxy_properties))

            for node in nodes:
                client_conf = node.get_file(CLIENT_CONF)
                client_properties = PropertiesFile.loads(client_conf)
                client_properties.update({'authPlugin': 'org.apache.pulsar.client.impl.auth.AuthenticationTls',
                                          'authParams': ('tlsCertFile:{dir}/admin.cert.pem,tlsKeyFile:'
                                                         '{dir}/admin.key-pk8.pem').format(dir=TLS_CLIENT_DIR)})
                node.put_file(CLIENT_CONF, PropertiesFile.dumps(client_properties))

    # start broker nodes and proxy node
    for node in broker_nodes:
        execute_node_command(node, '{}/bin/pulsar-daemon start broker'.format(PULSAR_HOME), quiet,
                             'Broker start failed')

    out_file = '{}/logs/pulsar-proxy-{}.{}.out'.format(PULSAR_HOME, proxy_node.hostname, cluster.network)
    execute_node_command(proxy_node, 'mkdir -p {}/logs'.format(PULSAR_HOME), quiet)
    execute_node_command(proxy_node,
                         'nohup {}/bin/pulsar proxy > "{}" 2>&1 < /dev/null &'.format(PULSAR_HOME, out_file),
                         quiet, 'Proxy start failed')

    logger.info('Performing health check on Pulsar cluster (%s) ...', args.pulsar_cluster_name)
    def condition(node, cluster_name, command):
        command_status = node.execute(command, quiet=True)
        return command_status.exit_code == 0 and command_status.output.strip() == cluster_name
    wait_for_condition(condition=condition, condition_args=[proxy_node, args.pulsar_cluster_name,
                                                            '{}/bin/pulsar-admin clusters list'.format(PULSAR_HOME)])

    logger.info('Pulsar cluster (%s) can be reached on docker network (%s):\n%s \n%s',
                args.pulsar_cluster_name, cluster.network,
                textwrap.indent('Web service URL: {}'.format(web_service_url), prefix='    '),
                textwrap.indent('Broker service URL: {}'.format(broker_service_url), prefix='    '))
    logger.log(logging.INFO if args.tls else -1,
               'Pulsar cluster (%s) can be reached securely on docker network (%s):\n%s \n%s',
               args.pulsar_cluster_name, cluster.network,
               textwrap.indent('Secure web service URL: {}'.format(web_service_url_tls), prefix='    '),
               textwrap.indent('Secure broker service URL: {}'.format(broker_service_url_tls), prefix='    '))


def execute_node_command(node, command, quiet, fail_message=None):
    command_out = node.execute(command, quiet=quiet)
    if fail_message and command_out.exit_code != 0:
        raise Exception('{} on node ({}) with exit code ({}). Full output:'
                        '\n{}'.format(command, node.hostname, command_out.exit_code,
                                      textwrap.indent(command_out.output, prefix='    ')))
