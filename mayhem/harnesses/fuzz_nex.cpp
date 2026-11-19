// NEX/RMC message decoder (src/Cemu/nex/nex.cpp, nexTypes.h, nexFriends.h): the layer above PRUDP that
// decodes the friend-server payloads with lengths taken from the wire.
//
// One input = one reassembled datagram, as nexService::updateNexServiceConnection receives it from
// prudpClient::ReceiveDatagram. Like that function it splits on nexIsRequest() and calls the real
// nexService_parseRequest / nexService_parseResponse. The parsed nexPacketBuffer then goes to the
// friends-service decoders the emulator registers for it:
//   - requests on protocol 0x64, methods 1/2: nexFriends_protocolNotification_processRequest ->
//     the real NexFriends::processServerNotification (nexPresenceV2 / nexNotificationEventGeneral /
//     nexFriendRequest / nexFriend via nexPacketBuffer::readPlaceholderType);
//   - responses on NEX_PROTOCOL_FRIENDS_WIIU, method 1: the real (private static)
//     NexFriends::handleResponse_getAllInformation (preference, comment, friend / request / blacklist /
//     notification lists, change tracking), the handler nexService invokes for that call's response.
// That handler and nexService's default constructor are private and reached only over a live
// connection, so the two headers are included with `private` mapped to `public` (access only: the class
// layouts are unchanged). Each input gets a fresh NexFriends whose nexCon is an offline nexService
// (no prudpClient): callMethod() only queues, so the handler's updatePreferencesAsync() path runs as
// upstream's does without a socket. Crash frames are upstream's (e.g. nexFriends.cpp:296
// `session->list_friends.resize(friendCount)` with a count from the wire).
#include "Common/precompiled.h"
#define private public
#include "Cemu/nex/nex.h"
#include "Cemu/nex/nexFriends.h"
#undef private

// defined in src/Cemu/nex/nex.cpp (no header declares them)
sint32 nexService_parseResponse(uint8* data, sint32 length, nexServiceResponse_t* response);
sint32 nexService_parseRequest(uint8* data, sint32 length, nexServiceRequest_t* request);
bool nexIsRequest(uint8* data, sint32 length);

// per input: a fresh, not-logged-in session (the constructor only stores these values)
struct FuzzSession
{
	uint8 miiData[FFL_SIZE] = {};
	uint16 miiNickname[11] = {'f', 'u', 'z', 'z', 0};
	nexPresenceV2 myPresence;
	NexFriends nexFriends{0, 0, "ridfebb9", 1, "", "", "fuzz", miiData, miiNickname, 0, myPresence};
	FuzzSession()
	{
		nexFriends.setNotificationHandler(nullptr); // the constructor leaves it unset
		nexFriends.firstInformationRequest = false; // also unset; false = a refresh, runs trackNotifications()
		nexFriends.nexCon = new nexService(); // offline: callMethod() only queues; freed by ~NexFriends
	}
};

// nexFriends.cpp nexFriends_protocolNotification_processRequest, minus its sendRequestResponse() ack
// (which needs the live connection): it reads type + pid and hands the rest to the real
// NexFriends::processServerNotification, which also updates the friend / request lists.
static void ProcessNotificationRequest(nexServiceRequest_t* request)
{
	if (request->methodId == 0x1 || request->methodId == 0x2)
	{
		uint32 notificationType = request->data.readU32();
		uint32 pid = request->data.readU32();
		if (request->data.hasReadOutOfBounds())
			return;
		FuzzSession session;
		session.nexFriends.processServerNotification(notificationType, pid, &request->data);
	}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	std::vector<uint8> bufferReceive(data, data + size);
	uint8* buf = bufferReceive.data();
	sint32 datagramLen = (sint32)size;
	if (datagramLen <= 0)
		return 0;
	if (nexIsRequest(buf, datagramLen))
	{
		nexServiceRequest_t request{};
		if (nexService_parseRequest(buf, datagramLen, &request) > 0 && request.protocolId == 0x64)
			ProcessNotificationRequest(&request);
	}
	else
	{
		nexServiceResponse_t response{};
		if (nexService_parseResponse(buf, datagramLen, &response) > 0 && response.isSuccessful &&
			response.protocolId == NEX_PROTOCOL_FRIENDS_WIIU)
		{
			if (response.methodId == 1)
			{
				FuzzSession session;
				NexFriends::handleResponse_getAllInformation(&response, &session.nexFriends, nullptr);
			}
		}
	}
	return 0;
}
