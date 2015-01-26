# Overview

The Apache Cassandra database is the right choice when you need scalability
and high availability without compromising performance. Linear scalability
and proven fault-tolerance on commodity hardware or cloud infrastructure
make it the perfect platform for mission-critical data. Cassandra's support
for replicating across multiple datacenters is best-in-class, providing lower
latency for your users and the peace of mind of knowing that you can survive
regional outages.

See [cassandra.apache.org](http://cassandra.apache.org) for more information.


# Deployment

Cassandra deployments are relatively simple in that they consist of a set of
Cassandra nodes which seed from each other to create a ring of servers:
    
    juju deploy -n3 cs:trusty/cassandra

The service units will deploy and will form a single ring.

New nodes can be added to scale up:

    juju add-unit cassandra


Nodes can be decommissioned to shrink the cluster:

    juju remove-unit cassandra

It is recommended to deploy at least 3 nodes and configure all your
keyspaces to have a replication factor of at least three. Using fewer
nodes or neglecting to set your keyspaces' replication settings means
your data is at risk and availability lower, as a failed unit may take
the only copy of data with it.



## Planning

- Do not attempt to store too much data per node. If you need more space,
  add more nodes. Most workloads work best with a capacity under 500GB
  per node.

- You need to keep 50% of your disk space free for Cassandra maintenance
  operations. If you expect your nodes to hold 500GB of data each, you
  will need a 1TB partition.

- Much more information can be found in the [Cassandra 2.1 documentation](http://www.datastax.com/documentation/cassandra/2.1/cassandra/planning/architecturePlanningAbout_c.html)


# Usage

To relate the Cassandra charm to a service that understands how to talk to
Cassandra using Thrift or the native Cassandra protocol::

    juju deploy cs:service-that-needs-cassandra
    juju add-relation service-that-needs-cassandra cassandra:database

Client charms need to provide nothing. The Cassandra service publishes the following connection settings and cluster information on the client's relation:

`username` and `password`:

    Authentication credentials. The cluster is configured to use
    the standard PasswordAuthenticator authentication provider, rather
    than the insecure default. You can use different credentials
    if you wish, using and account created through some other mechanism.
    
`host`:

    IP address to connect to.

`native_protocol_port`:

    Port for drivers and tools using the newer native protocol.

`rpc_port`:

    Port for drivers and tools using the legacy Thrift protocol.

`cluster_name`:

    The cluster name. A client service may be related to several
    Cassandra services, and this setting may be used to tell which
    services belong to which cluster.

`datacenter` and `rack`:

    The datacenter and rack units in this service belong to. Required for
    setting keyspace replication correctly.

The cluster is configured to use the recommended 'snitch'
(GossipingPropertyFileSnitch), so you will need to configure replication of
your keyspaces using the NetworkTopologyStrategy replica placement strategy.
For example, using the default datacenter named 'juju':

    CREATE KEYSPACE IF NOT EXISTS mydata WITH REPLICATION =
    { 'class': 'NetworkTopologyStrategy', 'juju': 3};


Although authentication is configured using the standard
PasswordAuthentication, by default no authorization is configured
and the provided credentials will have access to all data on the cluster.
For more granular permissions, you will need to set the authorizer
in the service configuration to CassandraAuthorizer and manually grant
permissions to the users.


# Known Limitations and Issues

This is the 'trusty' charm. Upgrade from the 'precise' charm is not supported.

The DataStax Enterprise variant of Cassandra cannot be tested by Juju's
open automated test environment, due to DataStax's policy of requiring
registration before downloading their software. While DSE hopefully works
with this charm, it cannot be fully supported and using standard Open Source
edition of Cassandra ('community') is recommended wherever possible.


# Contact Information

## Cassandra

- [Apache Cassandra homepage](http://cassandra.apache.org/)
- [Cassandra Getting Started](http://wiki.apache.org/cassandra/GettingStarted)
