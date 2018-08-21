======================================
Apache Pulsar topology for clusterdock
======================================

This repository houses the **Apache Pulsar** topology for `clusterdock`_.

.. _clusterdock: https://github.com/clusterdock/clusterdock

Usage
=====

Assuming you've already installed **clusterdock** (if not, go `read the docs`_),
you use this topology by cloning it to a local folder and then running commands
with the ``clusterdock`` script:

.. _read the docs: http://clusterdock.readthedocs.io/en/latest/

.. code-block:: console

    $ git clone https://github.com/clusterdock/topology_apache_pulsar.git
    $ pip3 install -r topology_apache_pulsar/requirements.txt
    $ clusterdock start topology_apache_pulsar

To see full usage instructions for the ``start`` action, use ``-h``/``--help``:

.. code-block:: console

    $ clusterdock start topology_apache_pulsar -h
    usage: clusterdock start [--always-pull] [-c name] [--namespace ns] [-n nw]
                             [-o sys] [-p port] [-r url] [-h]
                             [--proxy-node-name hostname] [--pulsar-version ver]
                             [--pulsar-cluster-name name] [--predictable]
                             [--tls {encryption,authentication}]
                             [--zookeeper-nodes node [node ...]]
                             [--broker-nodes node [node ...]]
                             topology

    Start a Pulsar cluster

    positional arguments:
      topology              A clusterdock topology directory

    optional arguments:
      --always-pull         Pull latest images, even if they're available locally
                            (default: False)
      -c name, --cluster-name name
                            Cluster name to use (default: None)
      --namespace ns        Namespace to use when looking for images (default:
                            None)
      -n nw, --network nw   Docker network to use (default: cluster)
      -o sys, --operating-system sys
                            Operating system to use for cluster nodes (default:
                            None)
      -p port, --port port  Publish node port to the host. The format should be
                            "<node name>:<node port>" or "<node name>:<host
                            port>-><node port>" (surrounding quotes are required).
                            Argument may be used more than once for multiple
                            ports. (default: None)
      -r url, --registry url
                            Docker Registry from which to pull images (default:
                            docker.io)
      -h, --help            show this help message and exit

    Pulsar arguments:
      --proxy-node-name hostname
                            Pulsar proxy node's host name (default: pulsar)
      --pulsar-version ver  Pulsar version to use (default: 2.1.0)
      --pulsar-cluster-name name
                            Pulsar cluster name to use (default: pulsar-cluster)
      --predictable         If specified, attempt to expose container ports to the
                            same port number on the host (default: False)
      --tls {encryption,authentication}
                            If specified, enable TLS encryption or authentication
                            for proxy and broker nodes (default: None)

    Node groups:
      --zookeeper-nodes node [node ...]
                            Nodes of the zookeeper-nodes group (default:
                            ['zookeeper-1'])
      --broker-nodes node [node ...]
                            Nodes of the broker-nodes group (default: ['broker-1',
                            'broker-2'])
