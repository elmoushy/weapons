"""
Image compression utilities for news service
"""
import io
from PIL import Image, ImageOps
import logging

logger = logging.getLogger(__name__)


class ImageCompressor:
    """
    Handles image compression and optimization for news service
    """
    
    # Default settings for different image types
    COMPRESSION_SETTINGS = {
        'main_image': {
            'max_width': 1920,
            'max_height': 1080,
            'quality': 85,
            'format': 'JPEG'
        },
        'gallery_image': {
            'max_width': 1200,
            'max_height': 800,
            'quality': 80,
            'format': 'JPEG'
        },
        'thumbnail': {
            'max_width': 300,
            'max_height': 200,
            'quality': 75,
            'format': 'JPEG'
        }
    }
    
    @staticmethod
    def compress_image(image_data, image_type='main_image', format_override=None):
        """
        Compress and optimize image data
        
        Args:
            image_data (bytes): Original image data
            image_type (str): Type of image (main_image, gallery_image, thumbnail)
            format_override (str): Override format (JPEG, PNG, WEBP)
        
        Returns:
            bytes: Compressed image data
        """
        if not image_data:
            return image_data
        
        try:
            # Get compression settings
            settings = ImageCompressor.COMPRESSION_SETTINGS.get(
                image_type, 
                ImageCompressor.COMPRESSION_SETTINGS['main_image']
            )
            
            # Override format if specified
            if format_override:
                settings = settings.copy()
                settings['format'] = format_override.upper()
            
            # Open image
            image = Image.open(io.BytesIO(image_data))
            
            # Convert RGBA to RGB if saving as JPEG
            if settings['format'] == 'JPEG' and image.mode in ('RGBA', 'LA', 'P'):
                # Create white background
                background = Image.new('RGB', image.size, (255, 255, 255))
                if image.mode == 'P':
                    image = image.convert('RGBA')
                background.paste(image, mask=image.split()[-1] if len(image.split()) > 3 else None)
                image = background
            
            # Auto-orient the image based on EXIF data
            image = ImageOps.exif_transpose(image)
            
            # Resize if needed
            original_size = image.size
            max_size = (settings['max_width'], settings['max_height'])
            
            if original_size[0] > max_size[0] or original_size[1] > max_size[1]:
                image.thumbnail(max_size, Image.Resampling.LANCZOS)
                logger.info(f"Resized image from {original_size} to {image.size}")
            
            # Compress and save
            output = io.BytesIO()
            
            if settings['format'] == 'WEBP':
                image.save(
                    output,
                    format='WEBP',
                    quality=settings['quality'],
                    optimize=True,
                    method=6  # Best compression
                )
            elif settings['format'] == 'PNG':
                image.save(
                    output,
                    format='PNG',
                    optimize=True
                )
            else:  # JPEG
                image.save(
                    output,
                    format='JPEG',
                    quality=settings['quality'],
                    optimize=True,
                    progressive=True
                )
            
            compressed_data = output.getvalue()
            
            # Log compression results
            original_size_kb = len(image_data) / 1024
            compressed_size_kb = len(compressed_data) / 1024
            compression_ratio = (1 - len(compressed_data) / len(image_data)) * 100
            
            logger.info(
                f"Image compressed: {original_size_kb:.1f}KB → {compressed_size_kb:.1f}KB "
                f"({compression_ratio:.1f}% reduction)"
            )
            
            return compressed_data
            
        except Exception as e:
            logger.error(f"Image compression failed: {e}")
            return image_data  # Return original if compression fails
    
    @staticmethod
    def generate_thumbnail(image_data, width=300, height=200):
        """
        Generate a thumbnail from image data
        
        Args:
            image_data (bytes): Original image data
            width (int): Thumbnail width
            height (int): Thumbnail height
        
        Returns:
            bytes: Thumbnail image data
        """
        try:
            image = Image.open(io.BytesIO(image_data))
            
            # Convert RGBA to RGB if needed
            if image.mode in ('RGBA', 'LA', 'P'):
                background = Image.new('RGB', image.size, (255, 255, 255))
                if image.mode == 'P':
                    image = image.convert('RGBA')
                background.paste(image, mask=image.split()[-1] if len(image.split()) > 3 else None)
                image = background
            
            # Auto-orient
            image = ImageOps.exif_transpose(image)
            
            # Create thumbnail maintaining aspect ratio
            image.thumbnail((width, height), Image.Resampling.LANCZOS)
            
            # Save as JPEG
            output = io.BytesIO()
            image.save(output, format='JPEG', quality=75, optimize=True)
            
            return output.getvalue()
            
        except Exception as e:
            logger.error(f"Thumbnail generation failed: {e}")
            return image_data
    
    @staticmethod
    def validate_image(image_data, max_size_mb=10):
        """
        Validate image data
        
        Args:
            image_data (bytes): Image data to validate
            max_size_mb (int): Maximum file size in MB
        
        Returns:
            tuple: (is_valid, error_message)
        """
        try:
            # Check file size
            size_mb = len(image_data) / (1024 * 1024)
            if size_mb > max_size_mb:
                return False, f"Image size ({size_mb:.1f}MB) exceeds maximum ({max_size_mb}MB)"
            
            # Try to open the image
            image = Image.open(io.BytesIO(image_data))
            image.verify()  # Verify it's a valid image
            
            # Check format
            if image.format not in ['JPEG', 'PNG', 'WEBP', 'BMP', 'TIFF']:
                return False, f"Unsupported image format: {image.format}"
            
            return True, None
            
        except Exception as e:
            return False, f"Invalid image: {str(e)}"
