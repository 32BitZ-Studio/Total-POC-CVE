#!/usr/bin/env python3
"""
Smart Sketch 2.0 - Upload Image
Uploads PNG or JPG images to the Smart Sketch projector unauthenticated
Created by David Rochester, 12/27/25
"""

import asyncio
from bleak import BleakClient, BleakScanner
from PIL import Image
import sys
import os

SERVICE_UUID = "0000ffe0-0000-1000-8000-00805f9b34fb" 
CHAR_UUID = "0000ffe3-0000-1000-8000-00805f9b34fb"

DEVICE_WIDTH = 160
DEVICE_HEIGHT = 120

class SmartSketchUploader:
    def __init__(self, client):
        self.client = client
        self.responses = []
    
    # helper to decode responses received from device
    def _notification_handler(self, sender, data):
        try:
            text = data.decode('ascii', errors='ignore')
            if text.strip():
                self.responses.append(text)
                print(f"  Device: {text}")
        except:
            pass
    
    # function to listen for responses from service char uuid, used to wait for OK response
    async def wait_for_response(self, expected, timeout=10):
        await self.client.start_notify(CHAR_UUID, self._notification_handler)
        
        start = asyncio.get_event_loop().time()
        while asyncio.get_event_loop().time() - start < timeout:
            for response in self.responses:
                if expected.lower() in response.lower():
                    await self.client.stop_notify(CHAR_UUID)
                    return True
            await asyncio.sleep(0.1)
        
        await self.client.stop_notify(CHAR_UUID)
        return False
    
    # load and resize image (supports PNG, JPG, JPEG)
    def load_and_prepare_image(self, image_path, target_width=DEVICE_WIDTH, target_height=DEVICE_HEIGHT):
        print(f"\nLoading image: {image_path}")
        
        # load image (PIL automatically handles PNG, JPG, JPEG)
        img = Image.open(image_path)
        print(f"  Original size: {img.size}")
        
        # convert to rgb
        if img.mode != 'RGB':
            print(f"  Converting from {img.mode} to RGB...")
            img = img.convert('RGB')
        
        # resize to fit smart sketch display
        if img.size != (target_width, target_height):
            print(f"  Resizing to {target_width}x{target_height}...")
            img = img.resize((target_width, target_height), Image.Resampling.LANCZOS)
        
        return img
    
    # function to convert RGB to RGB565 format that the device will understand
    def rgb_to_rgb565(self, img):
        width, height = img.size
        pixels = img.load()
        
        rgb565_data = bytearray()
        
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                
                r5 = (r >> 3) & 0x1F
                g6 = (g >> 2) & 0x3F
                b5 = (b >> 3) & 0x1F
                
                rgb565 = (r5 << 11) | (g6 << 5) | b5

                rgb565_data.append(rgb565 & 0xFF)
                rgb565_data.append((rgb565 >> 8) & 0xFF)
        
        return bytes(rgb565_data)
    
    # helper to reverse the image bytes, then split into chunks
    # CAN test this without reversing the bytes - should still work but will just flip image
    def prepare_chunks(self, rgb565_data, chunk_size=80):

        data = bytearray(rgb565_data)
        data.reverse()
        
        # chunk data
        chunks = []
        for i in range(0, len(data), chunk_size):
            chunks.append(bytes(data[i:i+chunk_size]))
        
        return chunks
    

    # function to complete the upload to device
    async def upload_image(self, image_path, chunk_size=80):
       
        print("="*70)
        print("SMART SKETCH - UNAUTHENTICATED IMAGE UPLOAD")
        print("="*70)
        
        # Load and prepare image
        img = self.load_and_prepare_image(image_path)
        
        # Convert to RGB565
        rgb565_data = self.rgb_to_rgb565(img)
        print(f"  RGB565 data: {len(rgb565_data)} bytes")
        
        # Prepare chunks
        chunks = self.prepare_chunks(rgb565_data, chunk_size)
        print(f"  Total chunks: {len(chunks)}")
        
        # Send command, 0x01 is SEND_IMAGE command
        print(f"\nSending COMMAND_SEND_IMAGE...")
        command = bytes([0x01, 0x00, 0x00, 0x00, chunk_size, 0x00, 0x02, 0x00]) 
        # write command to device
        await self.client.write_gatt_char(CHAR_UUID, command, response=False)
        
        if not await self.wait_for_response("OK"): # if we get OK response, ready to send image
            print("❌ Failed to get OK for command")
            return False
        
        print("  ✓ Device ready")
        
        # Start listening
        await self.client.start_notify(CHAR_UUID, self._notification_handler)
        
        # Send all chunks
        print(f"\nUploading {len(chunks)} chunks...")
        for i, chunk in enumerate(chunks):
            if i % 50 == 0:
                print(f"  Progress: {i}/{len(chunks)} ({int(i/len(chunks)*100)}%)")
            await self.client.write_gatt_char(CHAR_UUID, chunk, response=False)
            await asyncio.sleep(0.01)
        
        print(f"  Progress: {len(chunks)}/{len(chunks)} (100%)")
        print("  ✓ All chunks sent")
        
        # Wait for completion
        print(f"\nWaiting for device to process...")
        start = asyncio.get_event_loop().time()
        while asyncio.get_event_loop().time() - start < 20:
            for response in self.responses:
                if "done" in response.lower():
                    await self.client.stop_notify(CHAR_UUID)
                    print("\n" + "="*70)
                    print("✅ IMAGE SUCCESSFULLY UPLOADED!")
                    print("="*70)
                    print("\nCheck the Smart Sketch projector!")
                    return True
            await asyncio.sleep(0.1)
        
        await self.client.stop_notify(CHAR_UUID)
        print("\n⚠️  Upload completed but didn't receive 'Done'")
        print("   (This is normal - check if the image appeared on the projector)")
        return True


async def main():
    if len(sys.argv) < 2:
        print("Usage: python3 upload_image.py <image_file>")
        print("\nSupported formats: PNG, JPG, JPEG")
        print("\nExamples:")
        print("  python3 upload_image.py myimage.png")
        print("  python3 upload_image.py photo.jpg")
        sys.exit(1)
    
    image_path = sys.argv[1]
    
    if not os.path.exists(image_path):
        print(f"Error: File not found: {image_path}")
        sys.exit(1)
    
    # Check file extension
    file_ext = os.path.splitext(image_path)[1].lower()
    if file_ext not in ['.png', '.jpg', '.jpeg']:
        print(f"Error: Unsupported file format: {file_ext}")
        print("Supported formats: PNG, JPG, JPEG")
        sys.exit(1)
    
    print("="*70)
    print("Smart Sketch 2.0 - Unauthenticated image upload")
    print("="*70)
    print(f"\nImage file: {image_path}")
    
    # Find device
    print("\nScanning for Smart Sketch... make sure device is in range")
    devices = await BleakScanner.discover(timeout=5.0)
    
    smart_sketch = None
    for d in devices:
        # device tested on used name smART_Sketcher2.0
        if d.name and 'smart' in d.name.lower() and 'sketch' in d.name.lower():
            smart_sketch = d
            print(f"Found: {d.name} ({d.address})")
            break
    
    if not smart_sketch:
        print("❌ Device not found!")
        print("\nMake sure:")
        print("  - Smart Sketch is powered on")
        print("  - Not connected to another device")
        print("  - Within Bluetooth range")
        return
    
    print(f"\nConnecting...")
    async with BleakClient(smart_sketch.address) as client:
        print("✓ Connected!")
        
        uploader = SmartSketchUploader(client)
        await uploader.upload_image(image_path)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()