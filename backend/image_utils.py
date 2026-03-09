import os
from PIL import Image
import io

def process_logo(file_stream, target_path, max_size=(300, 300)):
    """
    Resizes and compresses an image for use as a logo.
    :param file_stream: The uploaded file-like object.
    :param target_path: The absolute path to save the processed image.
    :param max_size: Tuple (width, height) for maximum dimensions.
    """
    try:
        # Open the image
        img = Image.open(file_stream)
        
        # Convert to RGB if necessary (e.g., handles RGBA/PNG transparency)
        if img.mode in ("RGBA", "P"):
            img = img.convert("RGB")
            
        # Resize while maintaining aspect ratio, but also ensures it fits within 300x300
        img.thumbnail(max_size, Image.Resampling.LANCZOS)
        
        # Save as optimized JPEG with lower quality for smaller file size
        img.save(target_path, "JPEG", optimize=True, quality=70)
        return True
    except Exception as e:
        print(f"Error processing image: {e}")
        return False
