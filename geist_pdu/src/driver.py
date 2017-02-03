import threading

from cloudshell.power.pdu.power_resource_driver_interface import PowerResourceDriverInterface
from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.context import InitCommandContext, ResourceCommandContext

from cloudshell.pdu.geist.logic.geist_handler import geist_autoload, geist_power_cycle, geist_power_on, geist_power_off

from cloudshell.shell.core.context import AutoLoadDetails

class GeistPduDriver(ResourceDriverInterface, PowerResourceDriverInterface):


    def cleanup(self):
        """
        Destroy the driver session, this function is called everytime a driver instance is destroyed
        This is a good place to close any open sessions, finish writing to log files
        """
        pass

    def __init__(self):
        """
        ctor must be without arguments, it is created with reflection at run time
        """
        pass

    def initialize(self, context):
        """
        Initialize the driver session, this function is called everytime a new instance of the driver is created
        This is a good place to load and cache the driver configuration, initiate sessions etc.
        :param InitCommandContext context: the context the command runs on
        """
        pass

    def get_inventory(self, context):
        """

        :param context: ResourceCommandContext
        :return: AutoloadDetails
        """
        return geist_autoload(context)

    def PowerCycle(self, context, ports, delay):
        for port in ports:
            geist_power_cycle(context, int(port.split('/')[-1]), delay)

    def PowerOn(self, context, ports):
        for port in ports:
            geist_power_on(context, int(port.split('/')[-1]))

    def PowerOff(self, context, ports):
        for port in ports:
            geist_power_off(context, int(port.split('/')[-1]))
