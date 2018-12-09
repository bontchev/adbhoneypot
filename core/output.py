import socket


class Output(object):
    """
    Abstract base class intended to be inherited by output plugins.
    """

    def __init__(self, sensor=None):
        
        if not sensor:
            self.sensor = CONFIG.get('honeypot', 'sensor_name', fallback=socket.gethostname())
        else:
            self.sensor = sensor

        self.start()

    def start(self):
        """
        Abstract method to initialize output plugin
        """
        pass

    def stop(self):
        """
        Abstract method to shut down output plugin
        """
        pass

    def write(self, event):
        """
        Handle a general event within the output plugin
        """
        pass
