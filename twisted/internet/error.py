# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Exceptions and errors for use in twisted.internet modules.
"""

from __future__ import division, absolute_import

import socket

from twisted.python import deprecate
from twisted.python.versions import Version


class BaseError(Exception):
    message = "An error occurred"

    def __init__(self, *args):
        # Only use the message from this class or instance;
        # else the class name is more descriptive than the
        # generic ConnectError.message
        self.message = (self.__dict__.get('message') or
                        self.__class__.__dict__.get('message') or
                        "%s (%s)" % (self.message, self.__class__.__name__))

        if args:
            self.message = '%s: %s' % (self.message, ' '.join(args))

        super(BaseError, self).__init__(self.message)


class BindError(BaseError):
    message = "An error occurred binding to an interface"


class CannotListenError(BindError):
    """
    This gets raised by a call to startListening, when the object cannotstart
    listening.

    @ivar interface: the interface I tried to listen on
    @ivar port: the port I tried to listen on
    @ivar socketError: the exception I got when I tried to listen
    @type socketError: L{socket.error}
    """
    def __init__(self, interface, port, socketError):
        self.interface = interface
        self.port = port
        self.socketError = socketError

        iface = self.interface or 'any'
        self.message = "Couldn't listen on %s:%s: %s." % (self.interface or 'any',
                                                          self.port,
                                                          self.socketError)
        super(CannotListenError, self).__init__()



class MulticastJoinError(BaseError):
    message = "An attempt to join a multicast group failed"



class MessageLengthError(BaseError):
    message = "Message is too long to send"



class DNSLookupError(BaseError, IOError):
    message = "DNS lookup failed"



class ConnectInProgressError(BaseError):
    message = "A connect operation was started and isn't done yet"


# connection errors

class ConnectError(BaseError):
    message = "An error occurred while connecting"

    def __init__(self, osError=None, string=""):
        self.osError = osError
        self.string = string

        s = (self.__dict__.get('message') or
                self.__class__.__dict__.get('message') or
                "%s (%s)" % (self.message, self.__class__.__name__))

        if self.osError:
            s = '%s: %s' % (s, self.osError)
        if self.string:
            s = '%s: %s' % (s, self.string)

        self.message = s

        super(ConnectError, self).__init__()



class ConnectBindError(ConnectError):
    message = "Couldn't bind"



class UnknownHostError(ConnectError):
    message = "Hostname couldn't be looked up"



class NoRouteError(ConnectError):
    message = "No route to host"



class ConnectionRefusedError(ConnectError):
    message = "Connection was refused by other side"



class TCPTimedOutError(ConnectError):
    message = "TCP connection timed out"



class BadFileError(ConnectError):
    message = "File used for UNIX socket is no good"



class ServiceNameUnknownError(ConnectError):
    message = "Service name given as port is unknown"



class UserError(ConnectError):
    message = "User aborted connection"



class TimeoutError(UserError):
    message = "User timeout caused connection failure"



class SSLError(ConnectError):
    message = "An SSL error occurred"



class VerifyError(BaseError):
    message = "Could not verify something that was supposed to be signed"



class PeerVerifyError(VerifyError):
    message = "The peer rejected our verify error"



class CertificateError(BaseError):
    message = "We did not find a certificate where we expected to find one"



try:
    import errno
    errnoMapping = {
        errno.ENETUNREACH: NoRouteError,
        errno.ECONNREFUSED: ConnectionRefusedError,
        errno.ETIMEDOUT: TCPTimedOutError,
    }
    if hasattr(errno, "WSAECONNREFUSED"):
        errnoMapping[errno.WSAECONNREFUSED] = ConnectionRefusedError
        errnoMapping[errno.WSAENETUNREACH] = NoRouteError
except ImportError:
    errnoMapping = {}



def getConnectError(e):
    """Given a socket exception, return connection error."""
    if isinstance(e, Exception):
        args = e.args
    else:
        args = e
    try:
        number, string = args
    except ValueError:
        return ConnectError(string=e)

    if hasattr(socket, 'gaierror') and isinstance(e, socket.gaierror):
        # Only works in 2.2 in newer. Really that means always; #5978 covers
        # this and other wierdnesses in this function.
        klass = UnknownHostError
    else:
        klass = errnoMapping.get(number, ConnectError)
    return klass(number, string)



class ConnectionClosed(BaseError):
    message = "Connection was closed, whether cleanly or non-cleanly"



class ConnectionLost(ConnectionClosed):
    message = "Connection to the other side was lost in a non-clean fashion"



class ConnectionAborted(ConnectionLost):
    """
    Connection was aborted locally, using
    L{twisted.internet.interfaces.ITCPTransport.abortConnection}.

    @since: 11.1
    """

    message = "Connection was aborted locally"



class ConnectionDone(ConnectionClosed):
    message = "Connection was closed cleanly"



class FileDescriptorOverrun(ConnectionLost):
    """
    A mis-use of L{IUNIXTransport.sendFileDescriptor} caused the connection to
    be closed.

    Each file descriptor sent using C{sendFileDescriptor} must be associated
    with at least one byte sent using L{ITransport.write}.  If at any point
    fewer bytes have been written than file descriptors have been sent, the
    connection is closed with this exception.
    """

    message = ("A mis-use of IUNIXTransport.sendFileDescriptor caused the "
               "connection to be closed")



class ConnectionFdescWentAway(ConnectionLost):
    """Uh""" #TODO



class AlreadyCalled(BaseError, ValueError):
    message = "Tried to cancel an already-called event"



class AlreadyCancelled(BaseError, ValueError):
   message = "Tried to cancel an already-cancelled event"



class PotentialZombieWarning(Warning):
    """
    Emitted when L{IReactorProcess.spawnProcess} is called in a way which may
    result in termination of the created child process not being reported.

    Deprecated in Twisted 10.0.
    """
    MESSAGE = (
        "spawnProcess called, but the SIGCHLD handler is not "
        "installed. This probably means you have not yet "
        "called reactor.run, or called "
        "reactor.run(installSignalHandler=0). You will probably "
        "never see this process finish, and it may become a "
        "zombie process.")

deprecate.deprecatedModuleAttribute(
    Version("Twisted", 10, 0, 0),
    "There is no longer any potential for zombie process.",
    __name__,
    "PotentialZombieWarning")



class ProcessDone(ConnectionDone):
    message = "A process has ended without apparent errors"

    def __init__(self, status):
        super(ProcessDone, self).__init__()
        self.exitCode = 0
        self.signal = None
        self.status = status



class ProcessTerminated(ConnectionLost):
    """
    A process has ended with a probable error condition

    @ivar exitCode: See L{__init__}
    @ivar signal: See L{__init__}
    @ivar status: See L{__init__}
    """
    def __init__(self, exitCode=None, signal=None, status=None):
        """
        @param exitCode: The exit status of the process.  This is roughly like
            the value you might pass to L{os.exit}.  This is L{None} if the
            process exited due to a signal.
        @type exitCode: L{int} or L{types.NoneType}

        @param signal: The exit signal of the process.  This is L{None} if the
            process did not exit due to a signal.
        @type signal: L{int} or L{types.NoneType}

        @param status: The exit code of the process.  This is a platform
            specific combination of the exit code and the exit signal.  See
            L{os.WIFEXITED} and related functions.
        @type status: L{int}
        """
        self.exitCode = exitCode
        self.signal = signal
        self.status = status
        s = "process ended"
        if exitCode is not None: s = s + " with exit code %s" % exitCode
        if signal is not None: s = s + " by signal %s" % signal
        self.message = s
        super(ProcessTerminated, self).__init__()



class ProcessExitedAlready(BaseError):
    message = "Requested operation cannot be performed as the process has already exited"



class NotConnectingError(BaseError, RuntimeError):
    message = "The Connector was not connecting when it was asked to stop connecting"



class NotListeningError(BaseError, RuntimeError):
    message = "The Port was not listening when it was asked to stop listening"



class ReactorNotRunning(BaseError, RuntimeError):
    message = "Error raised when trying to stop a reactor which is not running"



class ReactorNotRestartable(BaseError, RuntimeError):
    message = "Error raised when trying to run a reactor which was stopped"



class ReactorAlreadyRunning(BaseError, RuntimeError):
    message = "Error raised when trying to start the reactor multiple times"



class ReactorAlreadyInstalledError(BaseError, AssertionError):
    message = "Could not install reactor because one is already installed"



class ConnectingCancelledError(BaseError):
    """
    An C{Exception} that will be raised when an L{IStreamClientEndpoint} is
    cancelled before it connects.

    @ivar address: The L{IAddress} that is the destination of the
        cancelled L{IStreamClientEndpoint}.
    """

    def __init__(self, address):
        """
        @param address: The L{IAddress} that is the destination of the
            L{IStreamClientEndpoint} that was cancelled.
        """
        self.message = address
        super(ConnectingCancelledError, self).__init__()



class UnsupportedAddressFamily(BaseError):
    """
    An attempt was made to use a socket with an address family (eg I{AF_INET},
    I{AF_INET6}, etc) which is not supported by the reactor.
    """



class UnsupportedSocketType(BaseError):
    """
    An attempt was made to use a socket of a type (eg I{SOCK_STREAM},
    I{SOCK_DGRAM}, etc) which is not supported by the reactor.
    """


class AlreadyListened(BaseError):
    """
    An attempt was made to listen on a file descriptor which can only be
    listened on once.
    """


__all__ = [
    'BindError', 'CannotListenError', 'MulticastJoinError',
    'MessageLengthError', 'DNSLookupError', 'ConnectInProgressError',
    'ConnectError', 'ConnectBindError', 'UnknownHostError', 'NoRouteError',
    'ConnectionRefusedError', 'TCPTimedOutError', 'BadFileError',
    'ServiceNameUnknownError', 'UserError', 'TimeoutError', 'SSLError',
    'VerifyError', 'PeerVerifyError', 'CertificateError',
    'getConnectError', 'ConnectionClosed', 'ConnectionLost',
    'ConnectionDone', 'ConnectionFdescWentAway', 'AlreadyCalled',
    'AlreadyCancelled', 'PotentialZombieWarning', 'ProcessDone',
    'ProcessTerminated', 'ProcessExitedAlready', 'NotConnectingError',
    'NotListeningError', 'ReactorNotRunning', 'ReactorAlreadyRunning',
    'ReactorAlreadyInstalledError', 'ConnectingCancelledError',
    'UnsupportedAddressFamily', 'UnsupportedSocketType']
