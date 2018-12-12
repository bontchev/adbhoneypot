from __future__ import print_function
import json
import core.output
from core.config import CONFIG


class Output(core.output.Output):

    def __init__(self, general_options):
        self.outfile = CONFIG.get('output_jsonlog', 'logfile')
        self.epoch_timestamp = CONFIG.getboolean('output_jsonlog', 'epoch_timestamp', fallback=False)

        core.output.Output.__init__(self, general_options)


    def start(self):
        pass

    def stop(self):
        pass

    def write(self, event):
        if not self.epoch_timestamp:
            event.pop('unixtime', None)
        with open(self.outfile, 'a') as f:
            print(json.dumps(event), file=f)
