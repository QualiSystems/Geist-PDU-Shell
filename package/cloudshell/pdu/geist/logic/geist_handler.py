import os
import threading

from cloudshell.shell.core.context import AutoLoadResource, AutoLoadDetails, AutoLoadAttribute
from cloudshell.snmp.quali_snmp import QualiSnmp

from cloudshell.networking.devices.driver_helper import get_snmp_parameters_from_command_context

from cloudshell.shell.core.session.logging_session import LoggingSessionContext

def get_logger(context):
    logger = LoggingSessionContext.get_logger_for_context(context)
    child = logger.getChild(threading.currentThread().name)
    for handler in logger.handlers:
        child.addHandler(handler)
    child.level = logger.level
    for log_filter in logger.filters:
        child.addFilter(log_filter)
    return child

def geist_autoload(context):
    logger = get_logger(context)
    snmp_parameters = get_snmp_parameters_from_command_context(context)
    snmp = QualiSnmp(snmp_parameters, logger)
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'mibs'))
    snmp.update_mib_sources(path)
    snmp.load_mib(['GEIST-MIB-V3'])

    def makeres(name, model, relative_address, unique_identifier='-1'):
        r = AutoLoadResource()
        r.name = name
        r.model = model
        r.relative_address = relative_address
        r.unique_identifier = unique_identifier

    def makeattr(relative_address, attribute_name, attribute_value):
        a = AutoLoadAttribute()
        a.relative_address = relative_address
        a.attribute_name = attribute_name
        a.attribute_value = attribute_value
        return a

    # snmp.get_property('SNMPv2-MIB', 'sysName')
    # snmp.get_property('SNMPv2-MIB', 'sysDescr')
    # snmp.get_property('SNMPv2-MIB', 'sysObjectID')
    # snmp.get_property('SNMPv2-MIB', 'sysContact')
    # snmp.get_property('SNMPv2-MIB', 'sysLocation')
    #
    # snmp.get_property('geistV3', 'productTitle')
    #
    # snmp.get_property('geistV3', 'productFriendlyName')
    # snmp.get_property('geistV3', 'productUrl')
    # snmp.get_property('geistV3', 'productHardware')
    #
    # snmp.get_property('geistV3', 'productHardware')
    #
    # snmp.get_property('SNMPv2-MIB', 'sysName')
    # snmp.get_property('SNMPv2-MIB', 'sysDescr')
    # snmp.get_property('SNMPv2-MIB', 'sysObjectID')
    # snmp.get_property('SNMPv2-MIB', 'sysContact')
    # snmp.get_property('SNMPv2-MIB', 'sysLocation')
    #
    # snmp.get_property('geistV3', 'productTitle')
    #
    # snmp.get_property('geistV3', 'productFriendlyName')
    # snmp.get_property('geistV3', 'productUrl')
    # snmp.get_property('geistV3', 'productHardware')
    #
    # snmp.get_property('geistV3', 'productHardware')
    #                 <AttributeValue Name="User" Value="" />
    #             <AttributeValue Name="Password" Value="3M3u7nkDzxWb0aJ/IZYeWw==" />
    #             <AttributeValue Name="Vendor" Value="" />
    #             <AttributeValue Name="Location" Value="" />
    #             <AttributeValue Name="Model" Value="" />
    #             <AttributeValue Name="Backup Location" Value="" />
    #             <AttributeValue Name="SNMP Read Community" Value="" />
    #             <AttributeValue Name="SNMP Write Community" Value="" />
    #             <AttributeValue Name="SNMP V3 Password" Value="" />
    #             <AttributeValue Name="SNMP V3 Private Key" Value="" />
    #             <AttributeValue Name="SNMP V3 User" Value="" />
    #             <AttributeValue Name="SNMP Version" Value="" />
    #             <AttributeValue Name="Console Server IP Address" Value="" />
    #             <AttributeValue Name="Console User" Value="" />
    #             <AttributeValue Name="Console Password" Value="3M3u7nkDzxWb0aJ/IZYeWw==" />
    #             <AttributeValue Name="Console Port" Value="0" />
    #             <AttributeValue Name="CLI Connection Type" Value="Auto" />

    rv = AutoLoadDetails()
    rv.resources = []
    rv.attributes = []

    rv.attributes.append(makeattr('', 'Version', snmp.get_property('GEIST-MIB-V3', 'productVersion', 0)))
    rv.attributes.append(makeattr('', 'Location', snmp.get_property('SNMPv2-MIB', 'sysLocation', 0)))
    rv.attributes.append(makeattr('', 'Vendor', snmp.get_property('GEIST-MIB-V3', 'productHardware', 0)))
    rv.attributes.append(makeattr('', 'Model', snmp.get_property('GEIST-MIB-V3', 'productTitle', 0)))

    outlet_table = snmp.get_table('GEIST-MIB-V3', 'ctrlOutletTable')

    for idx, record in outlet_table.iteritems():
                # <AttributeValue Name="Model" Value="" />
        # <AttributeValue Name="Serial Number" Value="" />
        # <AttributeValue Name="Version" Value="" />
        # <AttributeValue Name="Port Description" Value="" />
        addr = '%d' % idx
        rv.resources.append(makeres('Port %d' % idx, 'Generic Power Port', addr))
        rv.attributes.append(makeattr(addr, 'Port Description', record['ctrlOutletName']))

        # record['ctrlOutletStatus']
        # record['ctrlOutletFeedback']
        # record['ctrlOutletPending']
        # record['ctrlOutletDeciAmps']
        # record['ctrlOutletGroup']
        # record['ctrlOutletUpDelay']
        # record['ctrlOutletDwnDelay']
        # record['ctrlOutletRbtDuration']
        # record['ctrlOutletURL']
        # record['ctrlOutletPOAAction']
        # record['ctrlOutletPOADelay']
        # record['ctrlOutletkWattHrs']
        # record['ctrlOutletRbtDelay']
        # record['ctrlOutletStatusTime']

    return rv

        #
#     root_model.SYSTEM_NAME: self.snmp.get_property('SNMPv2-MIB', 'sysName', 0),
#     root_model.VENDOR: 'Cisco',
#     root_model.MODEL: self._get_device_model(),
#     root_model.LOCATION: self.snmp.get_property('SNMPv2-MIB', 'sysLocation',
#                                                      0),
#     root_model.CONTACT_NAME: self.snmp.get_property(
#         'SNMPv2-MIB', 'sysContact', 0),
#     root_model.OS_VERSION: ''}
#
#     match_version = re.search(r'Version\s+(?P<software_version>\S+)\S*\s+',
#     self.snmp.get_property('SNMPv2-MIB', 'sysDescr', 0))
#     if match_version:
#         result['os_version'] = match_version.groupdict()['software_version'].replace(',', '')
#
#     snmp.get_table('IF-MIB', "ifDescr")
# "entPhysicalDescr"