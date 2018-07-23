from PIL import Image

width = 200
height = 150

image_file = open('101.txt', 'rb')
data = image_file.read()
image = Image.frombuffer('RGB', (width, height), data, 'raw', 'RGB')
image = image.transpose(Image.FLIP_TOP_BOTTOM)
image.show()
image_file.close()
