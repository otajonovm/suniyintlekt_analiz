import React, { useState, useEffect, useRef } from "react";
import { 
  Shield, 
  Activity, 
  Terminal, 
  Bot, 
  Send, 
  RefreshCw, 
  Play, 
  Pause, 
  AlertTriangle, 
  CheckCircle, 
  FileText, 
  Sparkles, 
  HelpCircle,
  TrendingUp,
  Cpu,
  Fingerprint,
  Zap,
  Lock,
  MessageSquare,
  Network
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";

// Types definition
interface Packet {
  id: string;
  timestamp: string;
  sourceIP: string;
  destIP: string;
  protocol: "TCP" | "UDP" | "ICMP";
  packetSize: number;
  requestRate: number; // requests/sec from this IP
  payloadSignature: string; // Hex sequence representing payload
  type: "self" | "non-self";
  malwareType?: string;
  dangerSignalScore: number;
  pampScore: number;
  safeSignalScore: number;
  status: "Passed" | "Blocked" | "Analyzed";
}

interface ChatMessage {
  id: string;
  role: "user" | "model";
  text: string;
  timestamp: string;
}

interface NSA_Detector {
  id: string;
  centerSize: number;
  centerRate: number;
  centerSignature: string; // pattern matches
  radius: number; // threshold distance
  generation: number;
}

interface CSA_Bcell {
  id: string;
  signaturePattern: string;
  affinity: number; // o'xshashlik darajasi
  clonesCount: number;
  isMemoryCell: boolean;
}

export default function App() {
  // App states
  const [isPlaying, setIsPlaying] = useState<boolean>(true);
  const [selectedTab, setSelectedTab] = useState<"nsa" | "csa" | "dca" | "chat">("nsa");
  const [packets, setPackets] = useState<Packet[]>([]);
  const [blockedCount, setBlockedCount] = useState<number>(0);
  const [passedCount, setPassedCount] = useState<number>(0);
  const [nsaDetectors, setNsaDetectors] = useState<NSA_Detector[]>([]);
  const [csaBcells, setCsaBcells] = useState<CSA_Bcell[]>([]);
  const [dcaState, setDcaState] = useState({
    pampWeight: 2.0,
    dangerWeight: 1.5,
    safeWeight: 1.0,
    mcaValue: 0, // Mature DC activation threshold
    kValue: 0, // Anomaly index output
  });
  
  // Custom Packet Form
  const [customIp, setCustomIp] = useState<string>("192.168.1.105");
  const [customProtocol, setCustomProtocol] = useState<"TCP" | "UDP" | "ICMP">("TCP");
  const [customSize, setCustomSize] = useState<number>(200);
  const [customRate, setCustomRate] = useState<number>(10);
  const [customSig, setCustomSig] = useState<string>("73-79-73-74-65-6d");

  // Bot Chat States
  const [chatInput, setChatInput] = useState<string>("");
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([
    {
      id: "init-1",
      role: "model",
      text: "Salom! Men Sun'iy Immun Tizimi (AIS) tarmoq xavfsizligi botiman. Tarmoqdagi zararli dasturlarni aniqlash, Salbiy tanlash (NSA), Klon tanlash (CSA) yoki Dendrit hujayralari (DCA) algoritmlari haqida so'rang yoki tahlil qilish uchun tarmoq paketi ma'lumotlarini jo'nating!",
      timestamp: new Date().toLocaleTimeString(),
    },
  ]);
  const [isBotTyping, setIsBotTyping] = useState<boolean>(false);
  const chatEndRef = useRef<HTMLDivElement>(null);

  // Initialize Detectors and B-Cells
  useEffect(() => {
    // Generate initial Negative Selection Detectors
    const initialDetectors: NSA_Detector[] = [
      { id: "NSA-1", centerSize: 1400, centerRate: 150, centerSignature: "FF-00-A2-90", radius: 100, generation: 1 },
      { id: "NSA-2", centerSize: 850, centerRate: 180, centerSignature: "CC-CC-F0-99", radius: 80, generation: 1 },
      { id: "NSA-3", centerSize: 100, centerRate: 400, centerSignature: "BB-01-C3-DE", radius: 150, generation: 2 },
      { id: "NSA-4", centerSize: 1200, centerRate: 350, centerSignature: "44-55-66-77", radius: 120, generation: 3 },
    ];
    setNsaDetectors(initialDetectors);

    // Generate initial CSA B-Cells (Antibodies)
    const initialBcells: CSA_Bcell[] = [
      { id: "B-1", signaturePattern: "FF-00-A2-90", affinity: 0.85, clonesCount: 5, isMemoryCell: true },
      { id: "B-2", signaturePattern: "CC-CC-F0-99", affinity: 0.60, clonesCount: 2, isMemoryCell: false },
      { id: "B-3", signaturePattern: "AA-BB-CC-DD", affinity: 0.40, clonesCount: 1, isMemoryCell: false },
    ];
    setCsaBcells(initialBcells);

    // Initial simulated packets
    generateRandomPackets(5);
  }, []);

  // Handle auto-scroll on chatbot responses
  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [chatMessages, isBotTyping]);

  // Generate Simulated Traffic
  useEffect(() => {
    if (!isPlaying) return;

    const interval = setInterval(() => {
      // Create random packets
      const newPacket = createRandomPacket();
      processPacketThroughAIS(newPacket);
    }, 3000);

    return () => clearInterval(interval);
  }, [isPlaying, nsaDetectors, csaBcells, dcaState]);

  const createRandomPacket = (forceMalicious: "DDoS" | "PortScan" | "Trojan" | null = null): Packet => {
    const protocols: ("TCP" | "UDP" | "ICMP")[] = ["TCP", "UDP", "ICMP"];
    const randomProto = protocols[Math.floor(Math.random() * protocols.length)];
    const id = "PKT-" + Math.floor(100000 + Math.random() * 90000);
    const timestamp = new Date().toLocaleTimeString();

    let sourceIP = `192.168.1.${Math.floor(2 + Math.random() * 253)}`;
    let destIP = "10.0.0.15";
    let packetSize = Math.floor(64 + Math.random() * 1400);
    let requestRate = Math.floor(1 + Math.random() * 15);
    let payloadSignature = "45-74-68-65-72"; // Standard benign sequence
    let type: "self" | "non-self" = "self";
    let malwareType = undefined;

    // Signal scores for DCA simulation
    let pampScore = Math.random() * 2; // Pathogen signals (0 - 10)
    let dangerSignalScore = Math.random() * 3; // CPU, memory, anomaly alarms
    let safeSignalScore = 5 + Math.random() * 5; // Routine handshake, signed certificates

    // Inject malicious traffic based on random chance or force parameter
    const injectThreat = forceMalicious || (Math.random() > 0.7 ? "Random" : null);

    if (injectThreat) {
      type = "non-self";
      safeSignalScore = Math.random() * 2; // Low safety signal

      if (injectThreat === "DDoS" || (injectThreat === "Random" && Math.random() > 0.6)) {
        malwareType = "DDoS Hujum (Sin-Flood)";
        sourceIP = `172.16.5.${Math.floor(2 + Math.random() * 100)}`;
        packetSize = Math.floor(1200 + Math.random() * 300);
        requestRate = Math.floor(150 + Math.random() * 200); // Extremely high request rate
        payloadSignature = "FF-00-A2-90"; // Matches NSA-1 center
        pampScore = 7.5;
        dangerSignalScore = 9.0;
      } else if (injectThreat === "PortScan" || (injectThreat === "Random" && Math.random() > 0.3)) {
        malwareType = "Port Skonlash (Anomaliya)";
        sourceIP = `10.200.45.${Math.floor(2 + Math.random() * 254)}`;
        packetSize = Math.floor(64 + Math.random() * 128); // Small stealthy packets
        requestRate = Math.floor(60 + Math.random() * 40);
        payloadSignature = "CC-CC-F0-99"; // Matches NSA-2 center
        pampScore = 6.0;
        dangerSignalScore = 7.5;
      } else {
        malwareType = "Trojan Zararkunanda Paket";
        sourceIP = `185.220.101.${Math.floor(2 + Math.random() * 254)}`;
        packetSize = Math.floor(800 + Math.random() * 500);
        requestRate = Math.floor(2 + Math.random() * 8);
        payloadSignature = "BB-01-C3-DE"; // Matches NSA-3 center
        pampScore = 9.5;
        dangerSignalScore = 8.0;
      }
    }

    return {
      id,
      timestamp,
      sourceIP,
      destIP,
      protocol: randomProto,
      packetSize,
      requestRate,
      payloadSignature,
      type,
      malwareType,
      pampScore,
      dangerSignalScore,
      safeSignalScore,
      status: "Passed",
    };
  };

  const generateRandomPackets = (count: number) => {
    const list: Packet[] = [];
    for (let i = 0; i < count; i++) {
      const pkt = createRandomPacket();
      // Fast check
      const distanceMatched = nsaDetectors.some(det => {
        const sizeDiff = Math.abs(pkt.packetSize - det.centerSize);
        const rateDiff = Math.abs(pkt.requestRate - det.centerRate);
        const totalDist = Math.sqrt(sizeDiff * sizeDiff + rateDiff * rateDiff);
        return totalDist < det.radius || pkt.payloadSignature === det.centerSignature;
      });
      pkt.status = distanceMatched ? "Blocked" : "Passed";
      list.push(pkt);
    }
    setPackets(list);
    setBlockedCount(list.filter(p => p.status === "Blocked").length);
    setPassedCount(list.filter(p => p.status === "Passed").length);
  };

  // AIS Processing logic
  const processPacketThroughAIS = (pkt: Packet) => {
    let finalStatus: "Passed" | "Blocked" = "Passed";
    let triggerAlgorithm = "";

    // 1. NSA CHECK (Negative Selection Algorithm)
    // T-cells match foreign detectors if within threshold radius
    const nsaMatch = nsaDetectors.find(det => {
      // Euclidean distance based on packet size & request rate
      const sizeDiff = Math.abs(pkt.packetSize - det.centerSize);
      const rateDiff = Math.abs(pkt.requestRate - det.centerRate);
      const distance = Math.sqrt(sizeDiff * sizeDiff + rateDiff * rateDiff);
      
      // Matches signature pattern or falls within visual threshold distance
      const signatureMatch = pkt.payloadSignature === det.centerSignature;
      return distance < det.radius || signatureMatch;
    });

    if (nsaMatch) {
      finalStatus = "Blocked";
      triggerAlgorithm = "NSA (Salbiy Tanlash)";
    }

    // 2. CSA CHECK (Clonal Selection Algorithm)
    // B-cells dynamically bind to dangerous packet signature pattern
    const csaMatch = csaBcells.find(bcell => {
      return pkt.payloadSignature === bcell.signaturePattern && bcell.affinity > 0.5;
    });

    if (csaMatch) {
      finalStatus = "Blocked";
      triggerAlgorithm = "CSA (Klon Tanlash)";
      // Dynamic affinity maturation simulation
      setCsaBcells(prev => prev.map(b => {
        if (b.id === csaMatch.id) {
          return {
            ...b,
            affinity: Math.min(1.0, b.affinity + 0.05), // Increase binding strength
            clonesCount: b.clonesCount + 1,
            isMemoryCell: b.clonesCount > 5 ? true : b.isMemoryCell
          };
        }
        return b;
      }));
    }

    // 3. DCA CHECK (Dendritic Cell Algorithm)
    // Calculate DCA anomaly indicator k-value
    // k = (W_pamp * PAMP) + (W_danger * Danger) - (W_safe * Safe)
    const k = (dcaState.pampWeight * pkt.pampScore) + 
              (dcaState.dangerWeight * pkt.dangerSignalScore) - 
              (dcaState.safeWeight * pkt.safeSignalScore);

    if (k > 5.0) { // High threat index
      finalStatus = "Blocked";
      triggerAlgorithm = triggerAlgorithm ? `${triggerAlgorithm} + DCA` : "DCA (Dendrit Hujayralar)";
      
      // If a new threat is detected by DCA, clone it into the B-Cell population dynamically (Humoral Response)
      const existsInCsa = csaBcells.some(b => b.signaturePattern === pkt.payloadSignature);
      if (!existsInCsa && pkt.payloadSignature !== "45-74-68-65-72") {
        const newBcell: CSA_Bcell = {
          id: `B-Dyn-${Math.floor(100 + Math.random() * 900)}`,
          signaturePattern: pkt.payloadSignature,
          affinity: 0.55,
          clonesCount: 1,
          isMemoryCell: false
        };
        setCsaBcells(prev => [newBcell, ...prev]);
      }
    }

    pkt.status = finalStatus;
    
    // Update state lists
    setPackets(prev => [pkt, ...prev.slice(0, 19)]);
    if (finalStatus === "Blocked") {
      setBlockedCount(c => c + 1);
    } else {
      setPassedCount(c => c + 1);
    }
  };

  // Trigger explicit simulation events
  const handleSimulateAttack = (type: "DDoS" | "PortScan" | "Trojan") => {
    const pkt = createRandomPacket(type);
    processPacketThroughAIS(pkt);
  };

  // Create custom packet
  const handleSendCustomPacket = (e: React.FormEvent) => {
    e.preventDefault();
    const id = "PKT-CUST-" + Math.floor(1000 + Math.random() * 9000);
    const timestamp = new Date().toLocaleTimeString();

    // Estimate safe/dangerous signals based on size/signature
    const isSuspiciousSig = ["FF-00-A2-90", "CC-CC-F0-99", "BB-01-C3-DE"].includes(customSig);
    const isSuspiciousSize = customSize > 1200 && customRate > 80;

    const pkt: Packet = {
      id,
      timestamp,
      sourceIP: customIp,
      destIP: "10.0.0.15",
      protocol: customProtocol,
      packetSize: customSize,
      requestRate: customRate,
      payloadSignature: customSig,
      type: (isSuspiciousSig || isSuspiciousSize) ? "non-self" : "self",
      malwareType: isSuspiciousSig ? "Maxsus Kiritilgan Zararli Payload" : undefined,
      pampScore: isSuspiciousSig ? 8.5 : 1.0,
      dangerSignalScore: isSuspiciousSize ? 9.0 : 2.0,
      safeSignalScore: (isSuspiciousSig || isSuspiciousSize) ? 1.0 : 8.0,
      status: "Passed",
    };

    processPacketThroughAIS(pkt);
  };

  // Add a new Mature NSA detector manually
  const handleAddNsaDetector = () => {
    const id = `NSA-${nsaDetectors.length + 1}`;
    const centerSize = Math.floor(100 + Math.random() * 1300);
    const centerRate = Math.floor(10 + Math.random() * 300);
    const hexParts = ["AA", "BB", "00", "11", "99", "FF", "CC"];
    const centerSignature = `${hexParts[Math.floor(Math.random() * hexParts.length)]}-00-${hexParts[Math.floor(Math.random() * hexParts.length)]}-88`;
    
    const newDetector: NSA_Detector = {
      id,
      centerSize,
      centerRate,
      centerSignature,
      radius: Math.floor(60 + Math.random() * 100),
      generation: 1
    };

    setNsaDetectors(prev => [...prev, newDetector]);
  };

  // Chat request function
  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatInput.trim()) return;

    const userMsg: ChatMessage = {
      id: "usr-" + Date.now(),
      role: "user",
      text: chatInput,
      timestamp: new Date().toLocaleTimeString(),
    };

    setChatMessages(prev => [...prev, userMsg]);
    const promptToSend = chatInput;
    setChatInput("");
    setIsBotTyping(true);

    try {
      // Build history payload for server API
      const history = chatMessages.slice(-8).map(msg => ({
        role: msg.role,
        text: msg.text,
      }));

      const res = await fetch("/api/gemini/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: promptToSend, history }),
      });

      const data = await res.json();
      if (res.ok && data.text) {
        setChatMessages(prev => [...prev, {
          id: "bot-" + Date.now(),
          role: "model",
          text: data.text,
          timestamp: new Date().toLocaleTimeString(),
        }]);
      } else {
        throw new Error(data.error || "Ulanishda xatolik yuz berdi");
      }
    } catch (err: any) {
      console.error(err);
      setChatMessages(prev => [...prev, {
        id: "bot-err-" + Date.now(),
        role: "model",
        text: `Kechirasiz, xatolik yuz berdi: ${err.message || "Server javob bermadi"}. Gemini API kaliti sozlanmagan bo'lishi mumkin.`,
        timestamp: new Date().toLocaleTimeString(),
      }]);
    } finally {
      setIsBotTyping(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0c10] text-[#e1e1e1] font-sans flex flex-col overflow-x-hidden">
      
      {/* Header Section */}
      <header className="h-16 border-b border-[#1f2937] flex items-center justify-between px-8 bg-[#0d1117] sticky top-0 z-50">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-md bg-[#2563eb] flex items-center justify-center shadow-[0_0_15px_rgba(37,99,235,0.4)]">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-sm font-bold tracking-tight uppercase font-display flex items-center gap-2">
              AIS Malware Shield <span className="text-[#2563eb] text-xs font-mono font-medium opacity-90">v2.4.0</span>
            </h1>
            <p className="text-[10px] text-gray-500 font-mono hidden sm:block">
              SUN'IY IMMUN TIZIMLARI ASOSIDA TARMOQ HIMOYASI
            </p>
          </div>
        </div>

        <div className="flex items-center gap-6">
          <div className="hidden md:flex items-center gap-5">
            <div className="flex items-center gap-2">
              <span className={`w-2.5 h-2.5 rounded-full ${isPlaying ? "bg-green-500 animate-ping" : "bg-amber-500"}`}></span>
              <span className="text-xs font-mono text-gray-400">ALGORITM: ACTIVE</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-blue-400"></span>
              <span className="text-xs font-mono text-gray-400">BOT: INTEGRATED</span>
            </div>
          </div>

          <button 
            onClick={() => setIsPlaying(!isPlaying)}
            className={`px-4 py-1.5 rounded text-xs font-semibold flex items-center gap-1.5 transition-all ${
              isPlaying 
                ? "bg-[#1f2937] hover:bg-[#2d3748] border border-[#30363d] text-emerald-400" 
                : "bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-amber-400"
            }`}
          >
            {isPlaying ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            {isPlaying ? "Simulyator Faol" : "To'xtatildi"}
          </button>
        </div>
      </header>

      {/* Main Grid Layout */}
      <main className="flex-1 max-w-[1600px] w-full mx-auto p-6 grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        
        {/* Left Panel: Sidebar - Parameters & Attack Simulator */}
        <aside className="lg:col-span-3 flex flex-col gap-6 bg-[#0d1117] p-6 rounded-xl border border-[#1f2937] justify-between h-auto">
          <div className="space-y-6">
            <div>
              <h2 className="text-[10px] text-gray-500 uppercase tracking-widest mb-4 font-mono font-bold">Algoritm Parametrlari</h2>
              <div className="space-y-4">
                
                <div className="bg-[#161b22] p-3.5 rounded border border-[#30363d]">
                  <div className="text-[11px] text-blue-400 mb-1 flex items-center justify-between font-mono">
                    <span>PAMP (Patogen) Og'irligi</span>
                    <span className="text-[9px] text-slate-500">W_PAMP</span>
                  </div>
                  <div className="flex justify-between items-end">
                    <span className="text-2xl font-mono font-semibold text-slate-200">{dcaState.pampWeight.toFixed(1)}</span>
                    <span className="text-[10px] text-gray-500 mb-1 font-mono">MATCH RATE</span>
                  </div>
                </div>

                <div className="bg-[#161b22] p-3.5 rounded border border-[#30363d]">
                  <div className="text-[11px] text-purple-400 mb-1 flex items-center justify-between font-mono">
                    <span>Danger (Xavf) Og'irligi</span>
                    <span className="text-[9px] text-slate-500">W_DANGER</span>
                  </div>
                  <div className="flex justify-between items-end">
                    <span className="text-2xl font-mono font-semibold text-slate-200">{dcaState.dangerWeight.toFixed(1)}</span>
                    <span className="text-[10px] text-gray-500 mb-1 font-mono">SIGNAL INDEX</span>
                  </div>
                </div>

                <div className="bg-[#161b22] p-3.5 rounded border border-[#30363d]">
                  <div className="text-[11px] text-green-400 mb-1 flex items-center justify-between font-mono">
                    <span>Safe (Xavfsiz) Og'irligi</span>
                    <span className="text-[9px] text-slate-500">W_SAFE</span>
                  </div>
                  <div className="flex justify-between items-end">
                    <span className="text-2xl font-mono font-semibold text-slate-200">-{dcaState.safeWeight.toFixed(1)}</span>
                    <span className="text-[10px] text-gray-500 mb-1 font-mono">PRECISION</span>
                  </div>
                </div>

              </div>
            </div>

            {/* Simulated Attacks panel */}
            <div>
              <div className="flex items-center gap-2 mb-3">
                <Zap className="w-4 h-4 text-amber-500" />
                <h3 className="text-xs font-semibold uppercase tracking-widest text-slate-400 font-mono">Hujum Simulyatsiyasi</h3>
              </div>
              <p className="text-[11px] text-slate-400 mb-3.5 leading-relaxed">
                Immun tahlili sinovi uchun biologik antigenlarni simulyatsiya qilish:
              </p>
              <div className="space-y-2">
                <button
                  onClick={() => handleSimulateAttack("DDoS")}
                  className="w-full flex items-center justify-between p-2.5 bg-rose-950/20 hover:bg-rose-950/40 border border-rose-900/30 hover:border-rose-800/60 rounded text-left transition-all group"
                >
                  <span className="text-xs font-semibold text-rose-300 font-mono">DDoS Syn Flood</span>
                  <AlertTriangle className="w-4 h-4 text-rose-400 transition-transform group-hover:scale-110" />
                </button>
                <button
                  onClick={() => handleSimulateAttack("PortScan")}
                  className="w-full flex items-center justify-between p-2.5 bg-amber-950/20 hover:bg-amber-950/40 border border-amber-900/30 hover:border-amber-800/60 rounded text-left transition-all group"
                >
                  <span className="text-xs font-semibold text-amber-300 font-mono">Stealthy Port Scan</span>
                  <Activity className="w-4 h-4 text-amber-400 transition-transform group-hover:scale-110" />
                </button>
                <button
                  onClick={() => handleSimulateAttack("Trojan")}
                  className="w-full flex items-center justify-between p-2.5 bg-purple-950/20 hover:bg-purple-950/40 border border-purple-900/30 hover:border-purple-800/60 rounded text-left transition-all group"
                >
                  <span className="text-xs font-semibold text-purple-300 font-mono">Trojan Payload</span>
                  <Terminal className="w-4 h-4 text-purple-400 transition-transform group-hover:scale-110" />
                </button>
              </div>
            </div>
          </div>

          {/* Sidebar Status Info */}
          <div className="mt-6 p-4 rounded-lg bg-blue-950/20 border border-blue-500/20 shadow-inner">
            <div className="flex items-center gap-2.5 mb-2">
              <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></span>
              <span className="text-xs font-semibold text-blue-300 font-mono">Immun Tizimi Holati</span>
            </div>
            <p className="text-[11px] leading-relaxed text-slate-400">
              Tizim barcha tarmoq paketlarini antigen sifatida tahlil qilmoqda. Mutatsiya darajasi barqaror.
            </p>
          </div>
        </aside>

        {/* Middle Panel: Interactive Radar Visualization & Realtime traffic stream */}
        <section className="lg:col-span-5 flex flex-col gap-6">
          
          {/* Concentric AIS Radar Widget */}
          <div className="bg-[#0d1117] rounded-xl border border-[#30363d] p-5 relative overflow-hidden flex flex-col">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-display">Jonli Tarmoq Monitoringi (AIS Graph)</h3>
              <div className="flex gap-2">
                <span className={`px-2 py-0.5 text-[9px] font-mono rounded border uppercase ${
                  blockedCount > 0 
                    ? "bg-rose-500/10 border-rose-500/20 text-rose-400" 
                    : "bg-blue-500/10 border-blue-500/20 text-blue-400"
                }`}>
                  {blockedCount > 0 ? "Malware Detected" : "Scanning"}
                </span>
                <span className="px-2 py-0.5 text-[9px] bg-slate-800 border border-[#30363d] text-slate-400 rounded font-mono">
                  SCANNING: NODE 0xFF2
                </span>
              </div>
            </div>
            
            <div className="h-56 bg-[#0a0c10] rounded-xl border border-[#30363d]/50 relative overflow-hidden flex items-center justify-center">
              {/* Abstract Graphic Grid */}
              <div className="absolute inset-0 opacity-10" style={{ backgroundImage: "radial-gradient(#2563eb 0.5px, transparent 0.5px)", backgroundSize: "20px 20px" }}></div>
              
              {/* Concentric Circle Visualizer */}
              <div className="relative w-48 h-48 border-2 border-blue-500/10 rounded-full flex items-center justify-center">
                <div className="w-36 h-36 border border-blue-500/20 rounded-full animate-pulse"></div>
                <div className="w-24 h-24 border border-blue-500/40 rounded-full flex items-center justify-center">
                  <div className="w-12 h-12 border border-blue-500/60 rounded-full flex items-center justify-center">
                    <div className="w-3.5 h-3.5 bg-blue-500 rounded-full blur-[2px] animate-ping"></div>
                    <div className="w-2 h-2 bg-blue-500 rounded-full absolute"></div>
                  </div>
                </div>

                {/* Rotating Sweep Line */}
                <div className="absolute w-full h-full flex items-center justify-center">
                  <div className="absolute w-24 h-[1px] bg-gradient-to-r from-transparent via-blue-500/60 to-transparent rotate-45 opacity-50 animate-pulse"></div>
                  <div className="absolute w-24 h-[1px] bg-gradient-to-r from-transparent via-blue-500/60 to-transparent -rotate-45 opacity-50"></div>
                </div>

                {/* Floating Labels */}
                <div className="absolute -top-3 -left-3 p-1.5 bg-[#161b22] border border-[#30363d] text-[8px] font-mono rounded text-slate-400">
                  ID: ANTIGEN_{packets[0]?.id || "002"}
                </div>
                <div className={`absolute bottom-1 -right-3 p-1.5 border text-[8px] font-mono rounded ${
                  blockedCount > 0 
                    ? "bg-rose-950/50 border-rose-500/30 text-rose-400" 
                    : "bg-[#161b22] border-[#30363d] text-slate-400"
                }`}>
                  THREAT_LEVEL: {blockedCount > 0 ? "HIGH" : "SAFE"}
                </div>
              </div>
            </div>

            {/* Core Stats Bar */}
            <div className="h-20 mt-4 grid grid-cols-4 gap-3">
              <div className="border border-[#30363d] rounded-lg p-2.5 bg-[#161b22] flex flex-col justify-between">
                <div className="text-[8px] text-gray-500 uppercase font-mono tracking-wider">LATENCY</div>
                <div className="text-sm font-semibold font-mono text-slate-200">14ms</div>
              </div>
              <div className="border border-[#30363d] rounded-lg p-2.5 bg-[#161b22] flex flex-col justify-between">
                <div className="text-[8px] text-gray-500 uppercase font-mono tracking-wider">PASSED</div>
                <div className="text-sm font-semibold font-mono text-emerald-400">{passedCount}</div>
              </div>
              <div className="border border-[#30363d] rounded-lg p-2.5 bg-[#161b22] flex flex-col justify-between">
                <div className="text-[8px] text-gray-500 uppercase font-mono tracking-wider">BLOCKED</div>
                <div className="text-sm font-semibold font-mono text-rose-500">{blockedCount}</div>
              </div>
              <div className="border border-[#30363d] rounded-lg p-2.5 bg-[#161b22] flex flex-col justify-between">
                <div className="text-[8px] text-gray-500 uppercase font-mono tracking-wider">UPTIME</div>
                <div className="text-sm font-semibold font-mono text-blue-400">142h 02m</div>
              </div>
            </div>
          </div>

          {/* Real-time Traffic stream list */}
          <div className="bg-[#0d1117] rounded-xl border border-[#30363d] p-5 flex flex-col flex-1 min-h-[300px]">
            <div className="flex justify-between items-center mb-4 pb-2.5 border-b border-[#1f2937]">
              <div className="flex items-center gap-2">
                <Network className="w-4 h-4 text-blue-400" />
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-display">Jonli Tarmoq Trafiki Monitoringi</h4>
              </div>
              <button 
                onClick={() => {
                  setPackets([]);
                  setBlockedCount(0);
                  setPassedCount(0);
                }}
                className="text-[10px] text-slate-400 hover:text-slate-200 flex items-center gap-1 hover:underline font-mono"
              >
                <RefreshCw className="w-3 h-3" /> Tozalash
              </button>
            </div>

            <div className="flex-1 overflow-y-auto max-h-[280px] space-y-2.5 pr-1 scrollbar-thin scrollbar-thumb-[#1f2937]">
              {packets.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-slate-500 text-center">
                  <Activity className="w-8 h-8 text-slate-700 mb-2 animate-bounce" />
                  <p className="text-xs font-mono">Tarmoq trafigi kutilmoqda...</p>
                </div>
              ) : (
                <AnimatePresence initial={false}>
                  {packets.map((pkt) => (
                    <motion.div
                      key={pkt.id}
                      initial={{ opacity: 0, y: -5 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0 }}
                      className={`p-3 rounded border transition-all ${
                        pkt.status === "Blocked"
                          ? "bg-rose-950/10 border-rose-500/30"
                          : "bg-[#161b22] border-[#30363d]/80"
                      }`}
                    >
                      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-1 mb-1.5">
                        <div className="flex items-center gap-2">
                          <span className={`text-[8px] font-bold px-1.5 py-0.5 rounded font-mono ${
                            pkt.status === "Blocked" 
                              ? "bg-rose-500/10 text-rose-400 border border-rose-500/20" 
                              : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                          }`}>
                            {pkt.status === "Blocked" ? "NON-SELF" : "SELF"}
                          </span>
                          <span className="text-[10px] text-slate-500 font-mono">{pkt.timestamp}</span>
                          <span className="text-[10px] font-bold text-slate-300 font-mono">{pkt.id}</span>
                        </div>
                        
                        <div className="text-[10px] font-mono text-slate-400">
                          {pkt.protocol} • <span className="text-slate-300">{pkt.packetSize} B</span> • <span className="text-slate-300">{pkt.requestRate} req/s</span>
                        </div>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-1 pt-1.5 border-t border-[#30363d]/40">
                        <div className="text-[10px] text-slate-400 font-mono flex items-center gap-1.5">
                          IP: <span className="text-slate-200">{pkt.sourceIP}</span> ➜ <span className="text-slate-200">{pkt.destIP}</span>
                        </div>
                        <div className="text-[10px] text-slate-400 font-mono sm:text-right">
                          Signature: <span className="text-amber-400 font-medium">{pkt.payloadSignature}</span>
                        </div>
                      </div>

                      {pkt.status === "Blocked" && pkt.malwareType && (
                        <div className="mt-1.5 flex items-center gap-1.5 text-[9px] bg-rose-500/5 text-rose-300 p-1.5 rounded border border-rose-500/10 font-mono">
                          <AlertTriangle className="w-3 h-3 text-rose-400 shrink-0" />
                          <span><strong>Xavf:</strong> {pkt.malwareType}</span>
                        </div>
                      )}
                    </motion.div>
                  ))}
                </AnimatePresence>
              )}
            </div>
          </div>

          {/* Form Antigen Injector */}
          <div className="bg-[#0d1117] rounded-xl border border-[#30363d] p-5">
            <div className="flex items-center gap-2 mb-3">
              <Cpu className="w-4 h-4 text-blue-400" />
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-display">Maxsus Antigen Kiritish (Custom Packet)</h4>
            </div>

            <form onSubmit={handleSendCustomPacket} className="space-y-3.5">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div>
                  <label className="block text-[9px] text-gray-500 uppercase mb-1 font-mono font-semibold">IP Manba</label>
                  <input
                    type="text"
                    value={customIp}
                    onChange={(e) => setCustomIp(e.target.value)}
                    className="w-full bg-[#161b22] border border-[#30363d] rounded p-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-[9px] text-gray-500 uppercase mb-1 font-mono font-semibold">Protokol</label>
                  <select
                    value={customProtocol}
                    onChange={(e: any) => setCustomProtocol(e.target.value)}
                    className="w-full bg-[#161b22] border border-[#30363d] rounded p-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-blue-500"
                  >
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="ICMP">ICMP</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[9px] text-gray-500 uppercase mb-1 font-mono font-semibold">O'lcham (B)</label>
                  <input
                    type="number"
                    value={customSize}
                    onChange={(e) => setCustomSize(parseInt(e.target.value) || 0)}
                    className="w-full bg-[#161b22] border border-[#30363d] rounded p-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-[9px] text-gray-500 uppercase mb-1 font-mono font-semibold">Tezlik (req/s)</label>
                  <input
                    type="number"
                    value={customRate}
                    onChange={(e) => setCustomRate(parseInt(e.target.value) || 0)}
                    className="w-full bg-[#161b22] border border-[#30363d] rounded p-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              <div className="flex gap-2">
                <div className="flex-1">
                  <input
                    type="text"
                    value={customSig}
                    onChange={(e) => setCustomSig(e.target.value)}
                    placeholder="Payload Hex (masalan: FF-00-A2-90)"
                    className="w-full bg-[#161b22] border border-[#30363d] rounded p-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-blue-500"
                  />
                </div>
                <button
                  type="submit"
                  className="bg-[#2563eb] text-white hover:bg-blue-700 px-4 py-2 rounded text-xs font-semibold font-mono transition-all flex items-center gap-1 shrink-0"
                >
                  <Send className="w-3 h-3" /> INJECT
                </button>
              </div>
            </form>
          </div>

        </section>

        {/* Right Panel: AIS Tabs (NSA, CSA, DCA, Chat Bot) + Theoretical Guidelines */}
        <aside className="lg:col-span-4 flex flex-col gap-6">
          
          {/* Tabs header selector */}
          <div className="bg-[#0d1117] p-1 rounded-lg border border-[#1f2937] flex gap-0.5">
            <button
              onClick={() => setSelectedTab("nsa")}
              className={`flex-1 py-1.5 px-1 rounded text-[10px] font-mono font-bold tracking-tight uppercase transition-all ${
                selectedTab === "nsa" 
                  ? "bg-[#1f2937] text-blue-400 border border-[#30363d]" 
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              NSA (T-Cell)
            </button>
            <button
              onClick={() => setSelectedTab("csa")}
              className={`flex-1 py-1.5 px-1 rounded text-[10px] font-mono font-bold tracking-tight uppercase transition-all ${
                selectedTab === "csa" 
                  ? "bg-[#1f2937] text-cyan-400 border border-[#30363d]" 
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              CSA (B-Cell)
            </button>
            <button
              onClick={() => setSelectedTab("dca")}
              className={`flex-1 py-1.5 px-1 rounded text-[10px] font-mono font-bold tracking-tight uppercase transition-all ${
                selectedTab === "dca" 
                  ? "bg-[#1f2937] text-amber-400 border border-[#30363d]" 
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              DCA (Signals)
            </button>
            <button
              onClick={() => setSelectedTab("chat")}
              className={`flex-1 py-1.5 px-1 rounded text-[10px] font-mono font-bold tracking-tight uppercase flex items-center justify-center gap-1 transition-all ${
                selectedTab === "chat" 
                  ? "bg-[#1f2937] text-purple-400 border border-[#30363d]" 
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <Bot className="w-3 h-3" /> Chat Assist
            </button>
          </div>

          {/* Active Tab content container */}
          <div className="bg-[#0d1117] rounded-xl border border-[#1f2937] p-5 min-h-[380px] flex flex-col justify-between">
            
            {/* NSA Algorithm */}
            {selectedTab === "nsa" && (
              <div className="space-y-3.5 flex-1 flex flex-col justify-between">
                <div>
                  <div className="flex justify-between items-center mb-3">
                    <div className="flex items-center gap-2">
                      <Shield className="w-4 h-4 text-blue-400" />
                      <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-display">Salbiy Tanlash Algoritmi (NSA)</h4>
                    </div>
                    <button 
                      onClick={handleAddNsaDetector}
                      className="text-[9px] bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 border border-blue-500/20 px-2 py-0.5 rounded font-mono"
                    >
                      + ADD DETECTOR
                    </button>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed mb-3">
                    T-hujayralarining salbiy seleksiyasi printsipi bo'yicha ishlaydi. Sog'lom tarmoq ("self") holatiga reaktsiya bermaydigan mature detektorlar begona faollikni aniqlab darhol bloklaydi:
                  </p>
                  
                  <div className="space-y-2 max-h-[220px] overflow-y-auto pr-1">
                    {nsaDetectors.map(det => (
                      <div key={det.id} className="p-2.5 bg-[#161b22] rounded border border-[#30363d] flex justify-between items-center gap-2">
                        <div>
                          <div className="flex items-center gap-1.5">
                            <span className="text-xs font-bold text-blue-400 font-mono">{det.id}</span>
                            <span className="text-[8px] text-slate-500 uppercase font-mono">Mature Detector</span>
                          </div>
                          <div className="text-[10px] text-slate-400 font-mono mt-0.5">
                            Size: {det.centerSize}B • Rate: {det.centerRate}r/s
                          </div>
                          <div className="text-[10px] text-slate-500 font-mono">
                            Sig: <span className="text-amber-500">{det.centerSignature}</span>
                          </div>
                        </div>
                        <div className="text-right font-mono">
                          <div className="text-[8px] text-slate-500">RADIUS</div>
                          <div className="text-[11px] font-bold text-slate-300">{det.radius}px</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="bg-blue-950/10 p-3 rounded border border-blue-500/20 text-[10px] leading-relaxed text-blue-300 mt-4">
                  <strong>NSA printsipi:</strong> Detektorlar faqat begona "antigen" belgilarga nisbatan o'xshashlik tekshiruvi orqali signal beradi, bu esa yolg'on autoimmun reaksiyalarini (false positives) oldini oladi.
                </div>
              </div>
            )}

            {/* CSA Algorithm */}
            {selectedTab === "csa" && (
              <div className="space-y-3.5 flex-1 flex flex-col justify-between">
                <div>
                  <div className="flex justify-between items-center mb-3">
                    <div className="flex items-center gap-2">
                      <Fingerprint className="w-4 h-4 text-cyan-400" />
                      <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-display">Klon Tanlash Algoritmi (CSA)</h4>
                    </div>
                    <button 
                      onClick={() => {
                        setCsaBcells(prev => prev.map(b => ({
                          ...b,
                          affinity: Math.min(1.0, b.affinity + (Math.random() * 0.1)),
                          clonesCount: b.clonesCount + 1
                        })));
                      }}
                      className="text-[9px] bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/20 px-2 py-0.5 rounded font-mono"
                    >
                      MUTATE
                    </button>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed mb-3">
                    B-hujayralarining (antitelolar) moslashuvchan javob mexanizmi. Zararli signaturalar aniqlanganda, eng mos antitelolar klonlanadi va o'xshashlik kuchi ("affinity") oshib boradi:
                  </p>

                  <div className="space-y-2 max-h-[220px] overflow-y-auto pr-1">
                    {csaBcells.map(bcell => (
                      <div key={bcell.id} className="p-2.5 bg-[#161b22] rounded border border-[#30363d]">
                        <div className="flex justify-between items-center mb-1">
                          <div className="flex items-center gap-1.5">
                            <span className="text-xs font-bold text-cyan-400 font-mono">{bcell.id}</span>
                            {bcell.isMemoryCell ? (
                              <span className="text-[8px] text-amber-300 bg-amber-500/10 border border-amber-500/20 px-1 rounded font-mono">Memory</span>
                            ) : (
                              <span className="text-[8px] text-slate-500 font-mono">Cloned</span>
                            )}
                          </div>
                          <span className="text-[10px] text-slate-500 font-mono">Clones: {bcell.clonesCount}x</span>
                        </div>
                        <div className="text-[10px] text-slate-400 font-mono mb-1.5">
                          Payload Pattern: <span className="text-rose-400 font-semibold">{bcell.signaturePattern}</span>
                        </div>
                        <div className="space-y-0.5">
                          <div className="flex justify-between text-[9px] text-slate-500 font-mono">
                            <span>Afillik (affinity strength):</span>
                            <span>{(bcell.affinity * 100).toFixed(0)}%</span>
                          </div>
                          <div className="w-full h-1 bg-slate-800 rounded-full overflow-hidden">
                            <div 
                              className={`h-full rounded-full ${bcell.isMemoryCell ? 'bg-amber-400' : 'bg-cyan-400'}`}
                              style={{ width: `${bcell.affinity * 100}%` }}
                            />
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="bg-cyan-950/10 p-3 rounded border border-cyan-500/20 text-[10px] leading-relaxed text-cyan-300 mt-4">
                  <strong>Xotira tizimi:</strong> Yuqori afillikka erishgan B-hujayralar xotirada qoladi (Memory Cells). Keyingi safar xuddi shu zararli payload kelsa, reaksiya millisekundlarda sodir bo'ladi.
                </div>
              </div>
            )}

            {/* DCA Algorithm */}
            {selectedTab === "dca" && (
              <div className="space-y-3.5 flex-1 flex flex-col justify-between">
                <div>
                  <div className="flex items-center gap-2 mb-3">
                    <Activity className="w-4 h-4 text-amber-400" />
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-display">Dendrit Hujayralar Algoritmi (DCA)</h4>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed mb-3">
                    DCA biologik signallarni kontekstual tahlil qiladi. U uch xil signal og'irligidan foydalanib xavf indeksini (K-indeks) shakllantiradi:
                  </p>

                  <div className="bg-[#161b22] p-3 rounded border border-[#30363d] space-y-2.5 font-mono text-[10px]">
                    <div className="flex justify-between items-center border-b border-[#30363d]/50 pb-1.5">
                      <span className="text-rose-400 font-semibold">1. PAMP (Patogen Marker)</span>
                      <span className="text-slate-400">Multiplier: x{dcaState.pampWeight.toFixed(1)}</span>
                    </div>
                    <div className="flex justify-between items-center border-b border-[#30363d]/50 pb-1.5">
                      <span className="text-amber-400 font-semibold">2. Danger Signals (Xavf)</span>
                      <span className="text-slate-400">Multiplier: x{dcaState.dangerWeight.toFixed(1)}</span>
                    </div>
                    <div className="flex justify-between items-center border-b border-[#30363d]/50 pb-1.5">
                      <span className="text-emerald-400 font-semibold">3. Safe Signals (Xavfsiz)</span>
                      <span className="text-slate-400">Multiplier: -x{dcaState.safeWeight.toFixed(1)}</span>
                    </div>

                    <div className="pt-1.5 text-center">
                      <div className="text-[9px] text-slate-500 uppercase mb-1">DCA K-indeks formulasi</div>
                      <div className="bg-[#0a0c10] p-2 rounded border border-[#30363d] text-slate-300 font-bold">
                        k = (W_pamp * PAMP) + (W_ds * DS) - (W_ss * SS)
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-2 mt-3">
                    <div className="text-center p-1.5 bg-[#161b22] rounded border border-[#30363d]">
                      <div className="text-[8px] text-slate-500">PAMP (W)</div>
                      <div className="flex justify-center gap-1 mt-1">
                        <button 
                          onClick={() => setDcaState(s => ({ ...s, pampWeight: Math.max(0.5, s.pampWeight - 0.5) }))}
                          className="bg-slate-800 px-1 rounded text-[8px] hover:bg-slate-700"
                        >
                          -
                        </button>
                        <span className="text-[10px] font-bold font-mono">{dcaState.pampWeight.toFixed(1)}</span>
                        <button 
                          onClick={() => setDcaState(s => ({ ...s, pampWeight: Math.min(4.0, s.pampWeight + 0.5) }))}
                          className="bg-slate-800 px-1 rounded text-[8px] hover:bg-slate-700"
                        >
                          +
                        </button>
                      </div>
                    </div>

                    <div className="text-center p-1.5 bg-[#161b22] rounded border border-[#30363d]">
                      <div className="text-[8px] text-slate-500">Danger (W)</div>
                      <div className="flex justify-center gap-1 mt-1">
                        <button 
                          onClick={() => setDcaState(s => ({ ...s, dangerWeight: Math.max(0.5, s.dangerWeight - 0.5) }))}
                          className="bg-slate-800 px-1 rounded text-[8px] hover:bg-slate-700"
                        >
                          -
                        </button>
                        <span className="text-[10px] font-bold font-mono">{dcaState.dangerWeight.toFixed(1)}</span>
                        <button 
                          onClick={() => setDcaState(s => ({ ...s, dangerWeight: Math.min(4.0, s.dangerWeight + 0.5) }))}
                          className="bg-slate-800 px-1 rounded text-[8px] hover:bg-slate-700"
                        >
                          +
                        </button>
                      </div>
                    </div>

                    <div className="text-center p-1.5 bg-[#161b22] rounded border border-[#30363d]">
                      <div className="text-[8px] text-slate-500">Safe (W)</div>
                      <div className="flex justify-center gap-1 mt-1">
                        <button 
                          onClick={() => setDcaState(s => ({ ...s, safeWeight: Math.max(0.5, s.safeWeight - 0.5) }))}
                          className="bg-slate-800 px-1 rounded text-[8px] hover:bg-slate-700"
                        >
                          -
                        </button>
                        <span className="text-[10px] font-bold font-mono">{dcaState.safeWeight.toFixed(1)}</span>
                        <button 
                          onClick={() => setDcaState(s => ({ ...s, safeWeight: Math.min(4.0, s.safeWeight + 0.5) }))}
                          className="bg-slate-800 px-1 rounded text-[8px] hover:bg-slate-700"
                        >
                          +
                        </button>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="bg-amber-950/10 p-3 rounded border border-amber-500/20 text-[10px] leading-relaxed text-amber-300 mt-4">
                  <strong>DCA xususiyati:</strong> Faqat ma'lum bir zararkunanda imzosiga emas, balki tarmoqdagi barcha holatlarning "kontekstual" tahliliga imkon beradi. Ushbu algoritm hali o'rganilmagan Zero-day hujumlarini ham aniqlaydi.
                </div>
              </div>
            )}

            {/* Chatbot Helper */}
            {selectedTab === "chat" && (
              <div className="space-y-3.5 flex-1 flex flex-col justify-between h-full min-h-[340px]">
                <div>
                  <div className="flex items-center justify-between border-b border-[#1f2937] pb-2 mb-2">
                    <div className="flex items-center gap-1.5">
                      <div className="p-1 bg-purple-500/10 rounded text-purple-400 border border-purple-500/20">
                        <Bot className="w-3.5 h-3.5" />
                      </div>
                      <h4 className="text-[11px] font-bold text-slate-200 font-mono">Immun AI Assistenti</h4>
                    </div>
                    <span className="text-[8px] text-slate-500 font-mono bg-[#161b22] px-1.5 py-0.5 rounded border border-[#30363d]">
                      Gemini-3.5-Flash
                    </span>
                  </div>
                  <p className="text-[10px] text-slate-400 leading-relaxed">
                    AIS tarmoq xavfsizligi algoritmlarini tushunish, anomal log tahlili yoki maxsus immun qoidalarini yaratish haqida so'rang:
                  </p>
                </div>

                {/* Messages stream */}
                <div className="flex-1 overflow-y-auto max-h-[180px] space-y-2.5 my-2 pr-1 font-mono text-[10px] scrollbar-thin scrollbar-thumb-slate-800">
                  {chatMessages.map(msg => (
                    <div 
                      key={msg.id} 
                      className={`p-2.5 rounded max-w-[90%] border ${
                        msg.role === "user" 
                          ? "bg-purple-950/20 border-purple-800/40 text-purple-200 ml-auto" 
                          : "bg-[#161b22] border-[#30363d] text-slate-300 mr-auto"
                      }`}
                    >
                      <div className="flex justify-between items-center gap-4 mb-1 text-[8px] text-slate-500">
                        <span className="font-semibold uppercase">{msg.role === "user" ? "Siz" : "Immun-Bot"}</span>
                        <span>{msg.timestamp}</span>
                      </div>
                      <p className="whitespace-pre-line leading-relaxed select-text">{msg.text}</p>
                    </div>
                  ))}

                  {isBotTyping && (
                    <div className="bg-[#161b22] border border-[#30363d] p-2 rounded mr-auto max-w-[80%] font-mono text-[10px]">
                      <div className="flex items-center gap-2 text-slate-500">
                        <span className="w-1.5 h-1.5 bg-purple-500 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                        <span className="w-1.5 h-1.5 bg-purple-500 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                        <span className="w-1.5 h-1.5 bg-purple-500 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                        <span>Fikrlamoqda...</span>
                      </div>
                    </div>
                  )}
                  <div ref={chatEndRef} />
                </div>

                {/* Submit Form */}
                <form onSubmit={handleSendMessage} className="flex gap-2 border-t border-[#1f2937] pt-2.5">
                  <input
                    type="text"
                    value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)}
                    placeholder="Savolingizni kiriting..."
                    className="flex-1 bg-[#161b22] border border-[#30363d] rounded p-2 text-xs text-slate-200 focus:outline-none focus:border-purple-500 font-mono"
                  />
                  <button
                    type="submit"
                    disabled={isBotTyping}
                    className="bg-purple-600 hover:bg-purple-700 text-white px-3.5 py-2 rounded text-xs font-semibold flex items-center justify-center shrink-0 transition-all disabled:opacity-50"
                  >
                    <Send className="w-3.5 h-3.5" />
                  </button>
                </form>
              </div>
            )}

          </div>

          {/* Theoretical Guide Container */}
          <div className="bg-gradient-to-br from-[#0d1117] to-[#161b22] p-5 rounded-xl border border-[#1f2937] shadow-xl">
            <div className="flex items-center gap-2 mb-2.5">
              <HelpCircle className="w-4 h-4 text-emerald-400" />
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-display">AIS Nazariy Ma'lumot</h4>
            </div>

            <div className="space-y-2 text-[11px] text-slate-400 leading-relaxed font-mono">
              <p>
                <strong>Sun'iy Immun Tizimlari (AIS)</strong> - biologik immunologiyadan ilhomlangan moslashuvchan o'rganish tizimidir. Tarmoq xavfsizligida:
              </p>
              <ul className="list-disc list-inside space-y-1 bg-[#0a0c10]/40 p-2.5 rounded border border-[#30363d]/60 text-slate-400">
                <li><strong className="text-emerald-400">Self (Men)</strong> - sog'lom tarmoq faoliyati.</li>
                <li><strong className="text-rose-400">Non-Self (Yot)</strong> - zararkunanda va viruslar.</li>
                <li><strong className="text-cyan-400">Antigen</strong> - malware imzolash belgilari.</li>
                <li><strong className="text-amber-400">Afillik</strong> - tanib olish o'xshashlik kuchi.</li>
              </ul>
            </div>
          </div>

        </aside>

      </main>

      {/* Footer Bar Section */}
      <footer className="h-10 bg-[#0a0c10] border-t border-[#1f2937] flex items-center px-8 justify-between text-[10px] text-gray-500 font-mono sticky bottom-0">
        <div>ID: DEV_UNIT_042 // LOC: 192.168.1.100</div>
        <div className="flex gap-6">
          <span>CPU: 12%</span>
          <span>RAM: 4.2GB</span>
          <span className="text-[#2563eb] font-semibold">SISTEMA BARQAROR</span>
        </div>
      </footer>
    </div>
  );
}
