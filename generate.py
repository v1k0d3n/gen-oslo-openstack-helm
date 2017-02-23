#!/usr/bin/env python


import collections
import logging
import operator
import sys
import textwrap
import re

import pkg_resources
import six

from oslo_config._i18n import _LW
from oslo_config import cfg

from oslo_config.generator import register_cli_opts
from oslo_config.generator import _format_type_name, _generator_opts, _output_opts, _get_groups, _list_opts, _format_defaults

import stevedore.named  # noqa

LOG = logging.getLogger(__name__)
UPPER_CASE_GROUP_NAMES = ['DEFAULT']

class _HelmOptFormatter(object):

    """Format configuration option descriptions to a file."""

    def __init__(self, output_file=None, wrap_width=70, namespace=None):
        """Construct an OptFormatter object.

        :param output_file: a writeable file object
        :param wrap_width: The maximum length of help lines, 0 to not wrap
        """
        self.output_file = output_file or sys.stdout
        self.wrap_width = wrap_width

        # alanmeadows(TODO): this is a total hack and it does not provide a full path
        self.namespace = namespace[-1]

    def _format_help(self, help_text):
        """Format the help for a group or option to the output file.

        :param help_text: The text of the help string
        """
        if self.wrap_width is not None and self.wrap_width > 0:
            wrapped = ""
            for line in help_text.splitlines():
                text = "\n".join(textwrap.wrap(line, self.wrap_width,
                                               initial_indent='# ',
                                               subsequent_indent='# ',
                                               break_long_words=False,
                                               replace_whitespace=False))
                wrapped += "#" if text == "" else text
                wrapped += "\n"
            lines = [wrapped]
        else:
            lines = ['# ' + help_text + '\n']
        return lines

    def _get_choice_text(self, choice):
        if choice is None:
            return '<None>'
        elif choice == '':
            return "''"
        return six.text_type(choice)

    def format_group(self, group_or_groupname):
        """Format the description of a group header to the output file

        :param group_or_groupname: a cfg.OptGroup instance or a name of group
        :returns: a formatted group description string
        """
        if isinstance(group_or_groupname, cfg.OptGroup):
            group = group_or_groupname
            lines = ['[%s]\n' % group.name]
            if group.help:
                lines += self._format_help(group.help)
        else:
            groupname = group_or_groupname
            lines = ['[%s]\n' % groupname]
        self.writelines(lines)

    def format(self, opt, group_name, minimal=False, summarize=False):
        """Format a description of an option to the output file.

        :param opt: a cfg.Opt instance
        :param group_name: name of the group to which the opt is assigned
        :param minimal: enable option by default, marking it as required
        :param summarize: output a summarized description of the opt
        :returns: a formatted opt description string
        """
        if not opt.help:
            LOG.warning(_LW('"%s" is missing a help string'), opt.dest)

        opt_type = _format_type_name(opt.type)
        opt_prefix = ''
        if (opt.deprecated_for_removal and
                not opt.help.startswith('DEPRECATED')):
            opt_prefix = 'DEPRECATED: '

        if opt.help:
            # an empty line signifies a new paragraph. We only want the
            # summary line
            if summarize:
                _split = opt.help.split('\n\n')
                opt_help = _split[0].rstrip(':').rstrip('.')
                if len(_split) > 1:
                    opt_help += '. For more information, refer to the '
                    opt_help += 'documentation.'
            else:
                opt_help = opt.help

            help_text = u'%s%s (%s)' % (opt_prefix,
                                        opt_help,
                                        opt_type)
        else:
            help_text = u'(%s)' % opt_type
        lines = self._format_help(help_text)

        if getattr(opt.type, 'min', None) is not None:
            lines.append('# Minimum value: %d\n' % opt.type.min)

        if getattr(opt.type, 'max', None) is not None:
            lines.append('# Maximum value: %d\n' % opt.type.max)

        if getattr(opt.type, 'choices', None):
            choices_text = ', '.join([self._get_choice_text(choice)
                                      for choice in opt.type.choices])
            lines.append('# Allowed values: %s\n' % choices_text)

        try:
            if opt.mutable:
                lines.append(
                    '# Note: This option can be changed without restarting.\n'
                )
        except AttributeError as err:
            # NOTE(dhellmann): keystoneauth defines its own Opt class,
            # and neutron (at least) returns instances of those
            # classes instead of oslo_config Opt instances. The new
            # mutable attribute is the first property where the API
            # isn't supported in the external class, so we can use
            # this failure to emit a warning. See
            # https://bugs.launchpad.net/keystoneauth/+bug/1548433 for
            # more details.
            import warnings
            if not isinstance(opt, cfg.Opt):
                warnings.warn(
                    'Incompatible option class for %s (%r): %s' %
                    (opt.dest, opt.__class__, err),
                )
            else:
                warnings.warn('Failed to fully format sample for %s: %s' %
                              (opt.dest, err))

        for d in opt.deprecated_opts:
            lines.append('# Deprecated group/name - [%s]/%s\n' %
                         (d.group or group_name, d.name or opt.dest))

        if opt.deprecated_for_removal:
            if opt.deprecated_since:
                lines.append(
                    '# This option is deprecated for removal since %s.\n' % (
                        opt.deprecated_since))
            else:
                lines.append(
                    '# This option is deprecated for removal.\n')
            lines.append(
                '# Its value may be silently ignored in the future.\n')
            if opt.deprecated_reason:
                lines.extend(
                    self._format_help('Reason: ' + opt.deprecated_reason))

        if opt.advanced:
            lines.append(
                '# Advanced Option: intended for advanced users and not used\n'
                '# by the majority of users, and might have a significant\n'
                '# effect on stability and/or performance.\n'
            )

        if hasattr(opt.type, 'format_defaults'):
            defaults = opt.type.format_defaults(opt.default,
                                                opt.sample_default)
        else:
            LOG.debug(
                "The type for option %(name)s which is %(type)s is not a "
                "subclass of types.ConfigType and doesn't provide a "
                "'format_defaults' method. A default formatter is not "
                "available so the best-effort formatter will be used.",
                {'type': opt.type, 'name': opt.name})
            defaults = _format_defaults(opt)
        for default_str in defaults:
            if minimal:
                lines.append('{{- if .Values.%s.%s }}%s = {{ .Values.%s.%s | default \' %s\' }} {{- end}}\n' % (opt.dest, self.namespace, opt.dest, default_str))
            else:
                lines.append('#%s = {{ .Values.%s.%s | default \' %s\' }}\n' % (opt.dest, self.namespace, opt.dest, default_str))

        self.writelines(lines)

    def write(self, s):
        """Write an arbitrary string to the output file.

        :param s: an arbitrary string
        """
        self.output_file.write(s)

    def writelines(self, l):
        """Write an arbitrary sequence of strings to the output file.

        :param l: a list of arbitrary strings
        """
        self.output_file.writelines(l)

def generate(conf):
    """Generate a sample config file.

    List all of the options available via the namespaces specified in the given
    configuration and write a description of them to the specified output file.

    :param conf: a ConfigOpts instance containing the generator's configuration
    """
    conf.register_opts(_generator_opts)

    output_file = (open(conf.output_file, 'w')
                   if conf.output_file else sys.stdout)

    formatter = _HelmOptFormatter(output_file=output_file,
                              wrap_width=conf.wrap_width,
                              namespace=conf.namespace)

    groups = _get_groups(_list_opts(conf.namespace))

    # Output the "DEFAULT" section as the very first section
    _output_opts(formatter, 'DEFAULT', groups.pop('DEFAULT'), conf.minimal,
                 conf.summarize)

    # output all other config sections with groups in alphabetical order
    for group, group_data in sorted(groups.items()):
        formatter.write('\n\n')
        _output_opts(formatter, group, group_data, conf.minimal,
                     conf.summarize)



# generate helm defaults

def main(args=None):
    """The main function of oslo-config-generator."""
    version = pkg_resources.get_distribution('oslo.config').version
    logging.basicConfig(level=logging.WARN)
    conf = cfg.ConfigOpts()
    register_cli_opts(conf)
    conf(args, version=version)
    generate(conf)

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
