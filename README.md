# gen-oslo-openstack-helm
Oslo Config Generator Hack to Generate Helm Configs

# Usage

To generate a file similar to [etc/keystone.conf.sample](etc/keystone.conf.sample):

```
~/oslo-config/bin/python ./generate.py --config-file ../../openstack/keystone/config-generator/keystone.conf --namespace keystone
```

