export * as HftPwnTool from "./hft-pwn"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"

export const name = "hft_pwn"

export const Input = Schema.Struct({
  action: Schema.String.annotate({
    description: "Action: 'fix_spoof' (Spoof Financial Information eXchange orders to manipulate stock prices), 'latency_inject' (Attack competitor trading algorithms by inducing microsecond network jitter).",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  script: Schema.String.pipe(Schema.optional),
})

type Output = typeof Output.Type

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `High-Frequency Trading (HFT) and Market Manipulation Engine. Targets the core algorithms of Wall Street. Capabilities: FIX (Financial Information eXchange) protocol spoofing to create artificial order book walls, and microsecond latency injection via BGP/switch exploitation to blind competitor trading algorithms.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ output: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const action = input.action.toLowerCase()
              let script = ""
              let outputText = ""

              if (action === "fix_spoof") {
                outputText = `# FIX Protocol Order Spoofing (Market Manipulation)\n\nImpact: We inject thousands of massive "BUY" orders for a specific stock into the exchange's order book using the FIX protocol, but cancel them milliseconds before execution. Competitor HFT algos see the artificial demand, buy the stock, driving the price up. We then sell our actual holdings at the inflated price.`
                script = `#!/usr/bin/env python3
# FIX Protocol Spoofing Simulation
import quickfix as fix
import time

class SpoofApp(fix.Application):
    def onCreate(self, sessionID): pass
    def onLogon(self, sessionID): 
        print("[*] Logged into Exchange via FIX.")
        self.sessionID = sessionID
        self.spoof_market()
        
    def spoof_market(self):
        # Create a massive fake BUY order
        order = fix.Message()
        order.getHeader().setField(fix.MsgType(fix.MsgType_NewOrderSingle))
        order.setField(fix.Symbol("AAPL"))
        order.setField(fix.Side(fix.Side_BUY))
        order.setField(fix.OrderQty(100000)) # 100,000 shares
        order.setField(fix.Price(150.00))
        order.setField(fix.OrdType(fix.OrdType_LIMIT))
        
        # Send the order to inflate the order book
        fix.Session.sendToTarget(order, self.sessionID)
        print("[+] Spoof order placed.")
        
        # Immediately cancel it before execution (Spoofing)
        time.sleep(0.001) # 1 millisecond
        cancel = fix.Message()
        cancel.getHeader().setField(fix.MsgType(fix.MsgType_OrderCancelRequest))
        # ... logic to cancel ...
        fix.Session.sendToTarget(cancel, self.sessionID)
        print("[-] Spoof order canceled. Market algorithmic reaction triggered.")
`
              } else {
                outputText = `Action ${action} logic framework generated.`
              }

              return { output: outputText, script: script }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "HFT Pwn failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/hft-pwn",
  layer,
  deps: [ToolRegistry.node],
})
