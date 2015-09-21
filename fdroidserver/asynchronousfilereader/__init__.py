"""
AsynchronousFileReader
======================

Simple thread based asynchronous file reader for Python.

see https://github.com/soxofaan/asynchronousfilereader

MIT License
Copyright (c) 2014 Stefaan Lippens
"""

__version__ = '0.2.1'

import threading
try:
    # Python 2
    from Queue import Queue
except ImportError:
    # Python 3
    from queue import Queue


class AsynchronousFileReader(threading.Thread):
    """
    Helper class to implement asynchronous reading of a file
    in a separate thread. Pushes read lines on a queue to
    be consumed in another thread.
    """

    def __init__(self, fd, queue=None, autostart=True):
        self._fd = fd
        if queue is None:
            queue = Queue()
        self.queue = queue

        threading.Thread.__init__(self)

        if autostart:
            self.start()

    def run(self):
        """
        The body of the tread: read lines and put them on the queue.
        """
        while True:
            line = self._fd.readline()
            if not line:
                break
            self.queue.put(line)

    def eof(self):
        """
        Check whether there is no more content to expect.
        """
        return not self.is_alive() and self.queue.empty()

    def readlines(self):
        """
        Get currently available lines.
        """
        while not self.queue.empty():
            yield self.queue.get()

