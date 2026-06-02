import { AIBridge } from '../src/analyzer/aiBridge.js';

async function run() {
  console.log("Resetting...");
  const resetRes = await AIBridge.executeQuery({
    action: 'emulatorControl',
    params: { action: 'reset', entryPoint: 0x1000 }
  });
  console.log("Reset result:", resetRes);

  console.log("Writing memory...");
  const writeRes = await AIBridge.executeQuery({
    action: 'emulatorControl',
    params: {
      action: 'writeMem',
      memory: [{ address: '0x1000', value: '90' }]
    }
  });
  console.log("Write memory result:", writeRes);

  console.log("Stepping...");
  const stepRes = await AIBridge.executeQuery({
    action: 'emulatorControl',
    params: { action: 'step', steps: 1 }
  });
  console.log("Step result:", JSON.stringify(stepRes, null, 2));
}

run().catch(console.error);
