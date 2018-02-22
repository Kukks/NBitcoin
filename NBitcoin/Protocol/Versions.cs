using System;

namespace NBitcoin.Protocol
{
	public struct ProtocolVersion2
	{
		public ProtocolVersion2(ProtocolVersion protocolVersion)
		{
			Version = (uint) protocolVersion;
		}
		public ProtocolVersion2(uint protocolVersion)
		{
			Version = protocolVersion;
		}
		public uint Version { get; set; }
		public static implicit operator ProtocolVersion(ProtocolVersion2 d)
		{
			return (ProtocolVersion) d.Version;
		}
		public static implicit operator uint(ProtocolVersion2 d) 
		{
			return d.Version;
		}
		public static implicit operator ProtocolVersion2(ProtocolVersion d)
		{
			return new ProtocolVersion2(d);
		}
		public static implicit operator ProtocolVersion2(uint d)
		{
			return new ProtocolVersion2(d);
		}
	}

	/// <summary>
	/// Network protocol versioning
	/// </summary>
	public enum ProtocolVersion : uint
	{

		PROTOCOL_VERSION = 70012,

		/// <summary>
		/// Initial protocol version, to be increased after version/verack negotiation
		/// </summary>
		INIT_PROTO_VERSION = 209,

		/// <summary>
		/// Disconnect from peers older than this protocol version
		/// </summary>
		MIN_PEER_PROTO_VERSION = 209,

		/// <summary>
		/// nTime field added to CAddress, starting with this version;
		/// if possible, avoid requesting addresses nodes older than this
		/// </summary>
		CADDR_TIME_VERSION = 31402,

		/// <summary>
		/// Only request blocks from nodes outside this range of versions (START)
		/// </summary>
		NOBLKS_VERSION_START = 32000,

		/// <summary>
		/// Only request blocks from nodes outside this range of versions (END)
		/// </summary>
		NOBLKS_VERSION_END = 32400,

		/// <summary>
		/// BIP 0031, pong message, is enabled for all versions AFTER this one
		/// </summary>
		BIP0031_VERSION = 60000,

		/// <summary>
		/// "mempool" command, enhanced "getdata" behavior starts with this version
		/// </summary>
		MEMPOOL_GD_VERSION = 60002,

		/// <summary>
		/// "reject" command
		/// </summary>
		REJECT_VERSION = 70002,

		/// <summary>
		/// ! "filter*" commands are disabled without NODE_BLOOM after and including this version
		/// </summary>
		NO_BLOOM_VERSION = 70011,

		/// <summary>
		/// ! "sendheaders" command and announcing blocks with headers starts with this version
		/// </summary>
		SENDHEADERS_VERSION = 70012,

		/// <summary>
		/// ! Version after which witness support potentially exists
		/// </summary>
		WITNESS_VERSION = 70012,

		/// <summary>
		/// short-id-based block download starts with this version
		/// </summary>
		SHORT_IDS_BLOCKS_VERSION = 70014
}
}
