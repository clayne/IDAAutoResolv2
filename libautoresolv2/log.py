
import logging
from colorama import Fore, Style, init


class ColoredStreamHandler(logging.StreamHandler):
    def emit(self, record):
        try:
            msg = self.format(record)
            stream = self.stream
            if record.levelno == logging.DEBUG:
                stream.write(f'{Style.BRIGHT}{Fore.LIGHTWHITE_EX}{Style.RESET_ALL}{msg}\n')
            elif record.levelno == logging.INFO:
                stream.write(f'{Style.BRIGHT}{Fore.BLUE}{msg}{Style.RESET_ALL}\n')
            elif record.levelno == logging.WARNING:
                stream.write(f'{Style.BRIGHT}{Fore.YELLOW}{msg}{Style.RESET_ALL}\n')
            elif record.levelno == logging.ERROR:
                stream.write(f'{Fore.RED}{msg}{Style.RESET_ALL}\n')
            elif record.levelno == logging.CRITICAL:
                stream.write(f'{Style.BRIGHT}{Fore.RED}{msg}{Style.RESET_ALL}\n')
            else:
                stream.write(f'{msg}\n')


            with open("autoresolv2.log","a") as fd:
                fd.write(msg + "\n")
                fd.close()
            
            self.flush()
        except Exception as e:
            self.handleError(record)

class Logger:
    _logger = None

    @staticmethod
    def get_logger(verbose=None):
        if Logger._logger is None:
            Logger._logger = logging.getLogger(__name__)
            if verbose:
                Logger._logger.setLevel(logging.DEBUG)  # Set the desired logging level
            else:
                Logger._logger.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            stream_handler = ColoredStreamHandler()
            stream_handler.setFormatter(formatter)
            Logger._logger.addHandler(stream_handler)
            init()  # Initialize colorama
        return Logger._logger
    

logger = Logger.get_logger()
