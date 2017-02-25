# gen-oslo-openstack-helm
Oslo Config Generator Hack to Generate Helm Configs

# Usage

To generate a file similar to [etc/keystone.conf.sample](etc/keystone.conf.sample) resuming you have a virtual environment named `oslo-config` which satisfies both oslo-config-gen and keystone and the keystone source is in `../../openstack/keystone`:

```
~/oslo-config/bin/python ./generate.py --config-file ../../openstack/keystone/config-generator/keystone.conf --namespace keystone
```

