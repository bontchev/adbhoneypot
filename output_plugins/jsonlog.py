from __future__ import print_function
import os
import json
import copy
import errno
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
            # We need 'unixtime' value in some other plugins
            event_dump = copy.deepcopy(event)
            event_dump.pop('unixtime', None)
        else:
            event_dump = event
        if not os.path.exists(os.path.dirname(self.outfile)) and '/' in self.outfile:
            try:
                os.makedirs(os.path.dirname(self.outfile))
            except OSError as exc:
                if exc.errno != errno.EEXIST:
                    raise
        for key, value in event_dump.items():
            if type(value) == bytes:
                event_dump[key] = str(value, 'utf-8')
        with open(self.outfile, 'a') as f:
            print(json.dumps(event_dump), file=f)
