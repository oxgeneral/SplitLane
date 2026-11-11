import Foundation
import Network
import NetworkExtension

final class TCPRelay {
    private let flow: NEAppProxyTCPFlow
    private let connection: NWConnection
    private let queue: DispatchQueue
    private let onClose: () -> Void
    private var isOpen = false
    private var isClosed = false
    private var appFinished = false
    private var remoteFinished = false

    init(flow: NEAppProxyTCPFlow, parameters: NWParameters, queue: DispatchQueue, onClose: @escaping () -> Void) {
        self.flow = flow
        connection = NWConnection(to: flow.remoteFlowEndpoint, using: parameters)
        self.queue = queue
        self.onClose = onClose
    }

    func start() {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready: self.openFlow()
            case .failed(let error): self.stop(with: error)
            default: break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 12) { [weak self] in
            guard let self, !self.isOpen else { return }
            self.stop(with: NWError.posix(.ETIMEDOUT))
        }
    }

    func stop(with error: Error? = nil) {
        guard !isClosed else { return }
        isClosed = true
        connection.stateUpdateHandler = nil
        connection.cancel()
        let flowError = error.map { error in
            NSError(domain: NEAppProxyErrorDomain, code: NEAppProxyFlowError.aborted.rawValue,
                    userInfo: [NSUnderlyingErrorKey: error])
        }
        flow.closeReadWithError(flowError)
        flow.closeWriteWithError(flowError)
        onClose()
    }

    private func openFlow() {
        guard !isOpen, !isClosed else { return }
        flow.open(withLocalFlowEndpoint: nil) { [weak self] error in
            self?.queue.async { [weak self] in
                guard let self, !self.isClosed else { return }
                if let error { self.stop(with: error); return }
                self.isOpen = true
                self.readFromApp()
                self.readFromRemote()
            }
        }
    }

    private func readFromApp() {
        guard !isClosed else { return }
        flow.readData { [weak self] data, error in
            self?.queue.async { [weak self] in
                guard let self, !self.isClosed else { return }
                if let error { self.stop(with: error); return }
                let eof = data?.isEmpty != false
                self.connection.send(content: eof ? nil : data, contentContext: eof ? .finalMessage : .defaultMessage,
                                     isComplete: true, completion: .contentProcessed { error in
                    if let error { self.stop(with: error); return }
                    if eof {
                        self.appFinished = true
                        if self.remoteFinished { self.stop() }
                    } else {
                        self.readFromApp()
                    }
                })
            }
        }
    }

    private func readFromRemote() {
        guard !isClosed else { return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, eof, error in
            guard let self, !self.isClosed else { return }
            if let error { self.stop(with: error); return }
            if let data, !data.isEmpty {
                self.flow.write(data) { [weak self] error in
                    self?.queue.async { [weak self] in
                        guard let self, !self.isClosed else { return }
                        if let error { self.stop(with: error); return }
                        self.finishRemoteRead(eof)
                    }
                }
            } else {
                self.finishRemoteRead(eof)
            }
        }
    }

    private func finishRemoteRead(_ eof: Bool) {
        if eof {
            flow.closeWriteWithError(nil)
            remoteFinished = true
            if appFinished { stop() }
        } else {
            readFromRemote()
        }
    }
}
