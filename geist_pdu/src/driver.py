import threading

from cloudshell.power.pdu.power_resource_driver_interface import PowerResourceDriverInterface
from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.context import InitCommandContext, ResourceCommandContext

from package.cloudshell.pdu.geist.logic.geist_handler import geist_autoload


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

    def example_function(self, context):
        """
        A simple example function
        :param ResourceCommandContext context: the context the command runs on
        """
        pass

    def get_inventory(self, context):
        return geist_autoload(context)

    def PowerCycle(self, context, ports, delay):
        return super(GeistPduDriver, self).PowerCycle(context, ports, delay)

    def PowerOn(self, context, ports):
        return super(GeistPduDriver, self).PowerOn(context, ports)

    def PowerOff(self, context, ports):
        return super(GeistPduDriver, self).PowerOff(context, ports)
