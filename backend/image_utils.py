from PIL import Image, ImageOps
import io
import os

def process_logo(file_stream, target_path, size=(512, 512)):
    """
    Fits and compresses an image for use as a logo.
    :param file_stream: The uploaded file-like object.
    :param target_path: The absolute path to save the processed image.
    :param size: Tuple (width, height) for the final dimensions.
    """
    try:
        # Open the image
        img = Image.open(file_stream)
        
        # Ensure correct orientation based on EXIF
        img = ImageOps.exif_transpose(img)
        
        # Convert to RGBA clearly to handle transparency before fitting
        if img.mode != 'RGBA':
            img = img.convert('RGBA')
            
        # Fit logic (center crop to square by default)
        img = ImageOps.fit(img, size, Image.Resampling.LANCZOS)
        
        # Create a white background for non-transparent areas or if forced to RGB
        # Clients usually want a solid background for branding consistency
        final_img = Image.new("RGB", size, (255, 255, 255))
        final_img.paste(img, mask=img.split()[3]) # Use alpha as mask
        
        # Save as optimized JPEG
        final_img.save(target_path, "JPEG", optimize=True, quality=85)
        return True
    except Exception as e:
        print(f"Error processing image: {e}")
        return False
