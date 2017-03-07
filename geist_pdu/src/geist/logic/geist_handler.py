import os
import threading
from time import sleep

from cloudshell.shell.core.context import AutoLoadResource, AutoLoadDetails, AutoLoadAttribute
from cloudshell.shell.core.context_utils import get_attribute_by_name
from cloudshell.snmp.quali_snmp import QualiSnmp

from cloudshell.shell.core.session.logging_session import LoggingSessionContext
from cloudshell.snmp.snmp_parameters import SNMPV3Parameters, SNMPV2Parameters
from pysnmp.proto.rfc1902 import Gauge32
from pysnmp.smi.rfc1902 import ObjectType, ObjectIdentity


def get_logger(context):
    logger = LoggingSessionContext.get_logger_for_context(context)
    child = logger.getChild(threading.currentThread().name)
    for handler in logger.handlers:
        child.addHandler(handler)
    child.level = logger.level
    for log_filter in logger.filters:
        child.addFilter(log_filter)
    return child


def get_snmp_parameters_from_command_context(command_context, write):
    snmp_version = get_attribute_by_name(context=command_context, attribute_name='SNMP Version')
    ip = command_context.resource.address

    if '3' in snmp_version:
        return SNMPV3Parameters(
            ip=ip,
            snmp_user=get_attribute_by_name(context=command_context, attribute_name='SNMP User') or '',
            snmp_password=get_attribute_by_name(context=command_context, attribute_name='SNMP Password') or '',
            snmp_private_key=get_attribute_by_name(context=command_context, attribute_name='SNMP Private Key')
        )
    else:
        if write:
            community = get_attribute_by_name(context=command_context, attribute_name='SNMP Write Community') or 'private'
        else:
            community = get_attribute_by_name(context=command_context, attribute_name='SNMP Read Community') or 'public'
        return SNMPV2Parameters(ip=ip, snmp_community=community)


def do_geist_power(context, f, portstr):
    logger = get_logger(context)
    snmp_parameters = get_snmp_parameters_from_command_context(context, write=True)
    snmp = QualiSnmp(snmp_parameters, logger)
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'mibs'))
    snmp.update_mib_sources(path)
    snmp.load_mib(['GEIST-MIB-V3'])
    logger.info('geist power called with port "%s"' % portstr)
    f(snmp, portstr)


def geist_power_cycle(context, portstr, delay):
    def f(snmp, portstr):
        snmp._command(snmp.cmd_gen.setCmd, ObjectType(ObjectIdentity('GEIST-MIB-V3', 'ctrlOutletStatus', int(portstr)), Gauge32(3)))
        sleep(delay)
        snmp._command(snmp.cmd_gen.setCmd, ObjectType(ObjectIdentity('GEIST-MIB-V3', 'ctrlOutletStatus', int(portstr)), Gauge32(1)))

    do_geist_power(context, f, portstr)


def geist_power_on(context, portstr):
    def f(snmp, portstr):
        snmp._command(snmp.cmd_gen.setCmd, ObjectType(ObjectIdentity('GEIST-MIB-V3', 'ctrlOutletStatus', int(portstr)), Gauge32(1)))

    do_geist_power(context, f, portstr)


def geist_power_off(context, portstr):
    def f(snmp, portstr):
        snmp._command(snmp.cmd_gen.setCmd, ObjectType(ObjectIdentity('GEIST-MIB-V3', 'ctrlOutletStatus', int(portstr)), Gauge32(3)))

    do_geist_power(context, f, portstr)


def geist_autoload(context):
    logger = get_logger(context)
    snmp_parameters = get_snmp_parameters_from_command_context(context, write=False)
    snmp = QualiSnmp(snmp_parameters, logger)
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'mibs'))
    snmp.update_mib_sources(path)
    snmp.load_mib(['GEIST-MIB-V3'])

    def makeres(name, model, relative_address, unique_identifier):
        r = AutoLoadResource()
        r.name = name
        r.model = model
        r.relative_address = relative_address
        r.unique_identifier = unique_identifier
        return r

    def makeattr(relative_address, attribute_name, attribute_value):
        a = AutoLoadAttribute()
        a.relative_address = relative_address
        a.attribute_name = attribute_name
        a.attribute_value = attribute_value
        return a

    rv = AutoLoadDetails()
    rv.resources = []
    rv.attributes = []

    rv.attributes.append(makeattr('', 'Version', snmp.get_property('GEIST-MIB-V3', 'productVersion', 0)))
    rv.attributes.append(makeattr('', 'Location', snmp.get_property('SNMPv2-MIB', 'sysLocation', 0)))
    rv.attributes.append(makeattr('', 'Vendor', snmp.get_property('GEIST-MIB-V3', 'productHardware', 0)))
    rv.attributes.append(makeattr('', 'Model', snmp.get_property('GEIST-MIB-V3', 'productTitle', 0)))

    pduname = snmp.get_property('GEIST-MIB-V3', 'productFriendlyName', 0)

    outlet_table = snmp.get_table('GEIST-MIB-V3', 'ctrlOutletTable')

    for idx, record in outlet_table.iteritems():
        addr = '%d' % idx
        rv.resources.append(makeres('Port %d' % idx, 'Generic Power Socket', addr, '%s.%d' % (pduname, idx)))
        rv.attributes.append(makeattr(addr, 'Port Description', record['ctrlOutletName']))

    return rv
