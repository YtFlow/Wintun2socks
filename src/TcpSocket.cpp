#include "pch.h"
#include "TcpSocket.h"
#include <exception>

namespace PC = Platform::Collections;

namespace Wintun2socks {
	std::unordered_map<int, TcpSocket^> TcpSocket::m_socketmap;

	err_t TcpSocket::tcp_recv_func (void* arg, tcp_pcb *tpcb, pbuf *p, err_t err) {
		TcpSocket^ socket;
		if (TcpSocket::m_socketmap.find((int)arg) == TcpSocket::m_socketmap.end()) {
			if (p != NULL) {
				pbuf_free(p);
			}
			tcp_abort(tpcb);
			return ERR_ABRT;
		}
		socket = TcpSocket::m_socketmap[(int)arg];
		if (socket == nullptr) {
			if (p != NULL) {
				pbuf_free(p);
			}
			tcp_abort(tpcb);
			return ERR_ABRT;
		}
		if (p == NULL) {
			auto arr = ref new Platform::Array<uint8, 1>(0);
			socket->DataReceived(socket, arr);
			return ERR_OK;
		}
		auto arr = ref new Platform::Array<uint8, 1>(p->tot_len);
		pbuf_copy_partial(p, arr->begin(), p->tot_len, 0);
		socket->DataReceived(socket, arr);
		tcp_recved(tpcb, p->tot_len);
		pbuf_free(p);
		return ERR_OK;
	}
	err_t TcpSocket::tcp_sent_func (void* arg, tcp_pcb *tpcb, u16_t len) {
		if (arg == NULL) {
			tcp_abort(tpcb);
			return ERR_ABRT;
		}
		TcpSocket^ socket;
		if (TcpSocket::m_socketmap.find((int)arg) == TcpSocket::m_socketmap.end()) {
			tcp_abort(tpcb);
			return ERR_ABRT;
		}
		socket = TcpSocket::m_socketmap[(int)arg];
		if (socket == nullptr) {
			tcp_abort(tpcb);
			return ERR_ABRT;
		}
		socket->DataSent(socket, len);
		return ERR_OK;
	}
	err_t TcpSocket::tcpAcceptFn (void *arg, struct tcp_pcb *newpcb, err_t err) {
		TcpSocket^ newSocket = ref new TcpSocket(newpcb);
		TcpSocket::EstablishedTcp(newSocket);

		return ERR_OK;
	}
	err_t TcpSocket::tcp_err_func (void *arg, err_t err) {
		if (arg == NULL) return ERR_OK;
		TcpSocket^ socket;

		if (TcpSocket::m_socketmap.find((int)arg) == TcpSocket::m_socketmap.end()) {
			return ERR_ABRT;
		}
		socket = TcpSocket::m_socketmap[(int)arg];
		if (socket == nullptr) {
			return ERR_ABRT;
		}
		socket->SocketError(socket, err);
		return ERR_OK;
	}

	TcpSocket::TcpSocket(tcp_pcb *tpcb)
	{
		m_tcpb = tpcb;
		// Keep the last bit 1
		// 0 indicates the tcpb has been freed
		int arg = Random::Getone() | 0x1;
		tcp_arg(tpcb, (void*)arg);
		tcp_recv(tpcb, (tcp_recv_fn)&tcp_recv_func);
		tcp_sent(tpcb, (tcp_sent_fn)&tcp_sent_func);
		tcp_err(tpcb, (tcp_err_fn)&tcp_err_func);

		RemoteAddr = tpcb->local_ip.addr;
		RemotePort = tpcb->local_port;

		TcpSocket::m_socketmap[arg] = this;
	}
	void TcpSocket::Deinit() {
		m_socketmap.clear();
	}

	uint8 TcpSocket::Send(const Platform::Array<uint8, 1u>^ packet, bool more)
	{
		auto flag = 0;
		if (more) {
			flag |= TCP_WRITE_FLAG_MORE;
		}
		auto ret = tcp_write(m_tcpb, packet->begin(), packet->Length, flag);
		if (ret == ERR_OK) {
			return tcp_output(m_tcpb);
		}
		else return ret;
	}
	void TcpSocket::Recved(u16_t len) {
		tcp_recved(m_tcpb, len);
	}
	uint8 TcpSocket::Output() {
		auto ret = tcp_output(m_tcpb);
		return ret;
	}
	uint8 TcpSocket::Send(Windows::Storage::Streams::Buffer^ packet, bool more)
	{
		ComPtr<IBufferByteAccess> bufferByteAccess;
		reinterpret_cast<IInspectable*>(packet)->QueryInterface(IID_PPV_ARGS(&bufferByteAccess));
		byte* data = nullptr;
		bufferByteAccess->Buffer(&data);
		auto flag = TCP_WRITE_FLAG_COPY;
		if (more) {
			flag |= TCP_WRITE_FLAG_MORE;
		}
		auto ret = tcp_write(m_tcpb, data, packet->Length, flag);
		if (ret == ERR_OK) {
			return tcp_output(m_tcpb);
		}
		else return ret;
	}
	uint8 TcpSocket::Close()
	{
		if (m_released) return -1;
		m_released = true;
		TcpSocket::m_socketmap.erase((int)(m_tcpb->callback_arg));
		// tcp_arg(m_tcpb, NULL);
		tcp_recv(m_tcpb, NULL);
		tcp_sent(m_tcpb, NULL);
		tcp_err(m_tcpb, NULL);
		uint8 ret;
		if (m_tcpb->local_port == 0) {
			// Already closed
			// ret = tcp_close(m_tcpb);
			// tcp_abort(m_tcpb);
			ret = ERR_OK;
		}
		else {
			ret = tcp_close(m_tcpb);
		}
		return ret;
	}
	void TcpSocket::Abort()
	{
		if (m_released) return;
		m_released = true;
		int arg = (int)m_tcpb->callback_arg;
		TcpSocket::m_socketmap.erase((int)arg);
		tcp_arg(m_tcpb, NULL);
		tcp_recv(m_tcpb, NULL);
		tcp_sent(m_tcpb, NULL);
		tcp_err(m_tcpb, NULL);
		tcp_abort(m_tcpb);
	}
	TcpSocket::~TcpSocket()
	{
		this->Close();
	}
	unsigned int TcpSocket::ConnectionCount() {
		return m_socketmap.size();
	}
	u16_t TcpSocket::SendBufferSize::get() {
		return tcp_sndbuf(m_tcpb);
	}
}
