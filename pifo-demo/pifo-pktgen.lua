--- A simple UDP packet generator
local lm     = require "libmoon"
local device = require "device"
local stats  = require "stats"
local log    = require "log"
local memory = require "memory"

-- set addresses here
local DST_MAC       = "08:11:11:11:11:08"
local PKT_LEN       = 1000
local SRC_IP        = "10.0.0.10"
local DST_IP        = "10.1.0.10"
local SRC_PORT_BASE = 0 -- actual port will be SRC_PORT_BASE + random(0, NUM_FLOWS-1)
local DST_PORT      = 1234
local NUM_FLOWS     = 4


-- the configure function is called on startup with a pre-initialized command line parser
function configure(parser)
	parser:description("Edit the source to modify constants like IPs and ports.")
	parser:argument("dev", "Devices to use."):args("+"):convert(tonumber)
	parser:option("-t --threads", "Number of threads per device."):args(1):convert(tonumber):default(1)
	parser:option("-r --rate", "Transmit rate in Mbit/s per device."):args(1)
	parser:option("-o --output", "File to output statistics to")
	parser:option("-s --seconds", "Stop after n seconds")
	parser:flag("--csv", "Output in CSV format")
	return parser:parse()
end

function master(args,...)
	log:info("Starting packet generator ...")

	-- configure devices and queues
	for i, dev in ipairs(args.dev) do
		local dev = device.config{
			port = dev,
			txQueues = args.threads,
			rxQueues = 1
		}
		args.dev[i] = dev
	end
	device.waitForLinks()

	-- print statistics
	stats.startStatsTask{devices = args.dev, file = args.output, format = args.csv and "csv" or "plain"}

	-- configure tx rates and start transmit slaves
	for i, dev in ipairs(args.dev) do
		for i = 1, args.threads do
			local queue = dev:getTxQueue(i - 1)
			if args.rate then
				queue:setRate(args.rate / args.threads)
			end
			lm.startTask("txSlave", queue, DST_MAC)
		end
	end

	if args.seconds then
		lm.setRuntime(tonumber(args.seconds))
	end

	lm.waitForTasks()
end

function txSlave(queue, dstMac)
	-- memory pool with default values for all packets, this is our archetype
	local mempool = memory.createMemPool(function(buf)
		buf:getTcpPacket():fill{
			-- fields not explicitly set here are initialized to reasonable defaults
			ethSrc = queue, -- MAC of the tx device
			ethDst = dstMac,
			ip4Src = SRC_IP,
			ip4Dst = DST_IP,
			TcpSrc = SRC_PORT_BASE,
			TcpDst = DST_PORT,
			pktLength = PKT_LEN
		}
	end)
	-- a bufArray is just a list of buffers from a mempool that is processed as a single batch
	local bufs = mempool:bufArray()
	while lm.running() do -- check if Ctrl+c was pressed
		-- this actually allocates some buffers from the mempool the array is associated with
		-- this has to be repeated for each send because sending is asynchronous, we cannot reuse the old buffers here
		bufs:alloc(PKT_LEN)
		for i, buf in ipairs(bufs) do
			-- packet framework allows simple access to fields in complex protocol stacks
			local pkt = buf:getTcpPacket()
			pkt.tcp:setSrcPort(SRC_PORT_BASE + (i % NUM_FLOWS))
		end
--		bufs:offloadTcpChecksums()
		-- send out all packets and frees old bufs that have been sent
		queue:send(bufs)
	end
end

