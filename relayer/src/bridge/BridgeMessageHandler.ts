import { Packet } from "../network/RelayerService";

export interface BridgeMessage {
  id: string;
  sourceChain: string;
  destChain: string;
  packet: Packet;
  status: "pending" | "relayed" | "failed";
  createdAt: number;
  relayedAt?: number;
}

export class BridgeMessageHandler {
  private messages: Map<string, BridgeMessage> = new Map();

  async createMessage(packet: Packet): Promise<BridgeMessage> {
    const id = `msg-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const message: BridgeMessage = {
      id,
      sourceChain: packet.sourceChain,
      destChain: packet.destChain,
      packet,
      status: "pending",
      createdAt: Date.now(),
    };
    this.messages.set(id, message);
    return message;
  }

  async markRelayed(id: string): Promise<void> {
    const msg = this.messages.get(id);
    if (msg) {
      msg.status = "relayed";
      msg.relayedAt = Date.now();
      this.messages.set(id, msg);
    }
  }

  async markFailed(id: string): Promise<void> {
    const msg = this.messages.get(id);
    if (msg) {
      msg.status = "failed";
      this.messages.set(id, msg);
    }
  }

  getPendingMessages(): BridgeMessage[] {
    return Array.from(this.messages.values()).filter((m) => m.status === "pending");
  }

  getMessage(id: string): BridgeMessage | undefined {
    return this.messages.get(id);
  }
}
