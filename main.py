from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from pydantic import BaseModel
import mysql.connector
from typing import Optional
from fastapi import FastAPI, Query
from fastapi import FastAPI, File, UploadFile
import aiofiles
import os
import boto3
from botocore.client import Config
from fastapi.middleware.cors import CORSMiddleware
import shopify
import ssl
import requests
import json
from typing import List
import random
import base64
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from dotenv import load_dotenv  #la función config de decouple para cargar variables de entorno

ssl._create_default_https_context = ssl._create_unverified_context
load_dotenv()
DB_HOST = os.environ.get("DB_HOST")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_NAME = os.environ.get("DB_NAME")
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
AWS_REGION_NAME = os.environ.get("AWS_REGION_NAME")
AWS_ENDPOINT_URL = os.environ.get("AWS_ENDPOINT_URL")
SECRET_KEY = os.environ.get("SECRET_KEY")
SHOPIFY_API_TOKEN = os.environ.get("SHOPIFY_API_TOKEN")
SHOPIFY_STORE_NAME = os.environ.get("SHOPIFY_STORE_NAME")


adjetivos_sabor_premium = [
    # En inglés
    "Rich", "Luxurious", "Exquisite", "Gourmet", "Velvety",
    "Decadent", "Opulent", "Sumptuous", "Divine", "Indulgent",

    # En francés
    "Raffiné", "Luxueux", "Exquis", "Gourmand", "Onctueux",
    "Décadent", "Opulent", "Somptueux", "Divin", "Indulgent",

    # En español
    "Delicioso", "Exquisito", "Sabroso", "Gourmet", "Suave",
    "Lujoso", "Aterciopelado", "Rico", "Delicado", "Suntuoso",

    # Otros idiomas
    "Saporito", "Lecker", "Prelibato", "Buonissimo", "Delizioso",  # Italiano
    "Leckerbissen", "Erlesen", "Köstlich", "Wohlgeschmack", "Genussvoll",  # Alemán
    "Exquisito", "Saboroso", "Delicado", "Elegante", "Apetitoso",  # Portugués
]
# Conexión a la Base de Datos utilizando variables de entorno
connection = mysql.connector.connect(
    host=DB_HOST,
    port=3306,
    user=DB_USER,
    password=DB_PASSWORD,
    database=DB_NAME,
)

# Configuración de AWS utilizando variables de entorno
session = boto3.session.Session()
client = session.client(
    's3',
    region_name=AWS_REGION_NAME,
    endpoint_url=AWS_ENDPOINT_URL,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)

# Configuración de seguridad y tokens utilizando variables de entorno
SECRET_KEY = SECRET_KEY
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 5259600

# Modelos de Pydantic
class Token(BaseModel):
    access_token: str
    token_type: str

class ProductCheck(BaseModel):
    id: int
    quantity: int
    price: float
    name: str

class ProductListCheck(BaseModel):
    productos: List[ProductCheck]
    imagen: str  # Campo para la imagen en base64

class DataItem(BaseModel):
    id: int
    name: str
    photo: str
    precio: str
    largo: float
    ancho: float

class ProductData(BaseModel):
    title: str
    body_html: str
    vendor: str
    product_type: str
    status: str
    price: str

# Esta clase representa un usuario en tu sistema
class User(BaseModel):
    username: str

# Esto se usa para extraer el token del request
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Contexto para hashear y verificar contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Función para verificar la contraseña
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Función para hashear una contraseña
def get_password_hash(password):
    return pwd_context.hash(password)

# Función para autenticar al usuario
def authenticate_user(username: str, password: str):
    # Aquí deberías verificar las credenciales del usuario
    # con las almacenadas en tu base de datos
    return User(username=username)

# Función para crear un token de acceso
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Función para obtener el usuario actual
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = User(username=username)
    except JWTError:
        raise credentials_exception
    user = authenticate_user(token_data.username, "password") # Aquí deberías verificar el usuario
    if user is None:
        raise credentials_exception
    return user

# Configura CORS SOLO DEV!
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permite todas las fuentes. Cambia esto para mayor seguridad en producción
    allow_credentials=True,
    allow_methods=["*"],  # Permite todos los métodos
    allow_headers=["*"],  # Permite todas las cabeceras
)

# ... Otros imports y configuraciones aquí ...

# Endpoint para crear un elemento
@app.post("/items/")
async def create_item(name: str = Form(...), price: str = Form(...), category: str = Form(...), image: UploadFile = File(...), largo: int = Form(...), ancho: int = Form(...)):
    # Guardar temporalmente el archivo en el servidor
    temp_file_path = f"temp_{image.filename}"
    async with aiofiles.open(temp_file_path, 'wb') as out_file:
        content = await image.read()
        await out_file.write(content)

    # Subir el archivo a Digital Ocean Spaces
    with open(temp_file_path, 'rb') as file_data:
        client.upload_fileobj(
            Fileobj=file_data,
            Bucket="productos",
            Key=image.filename,
            ExtraArgs={'ACL': 'public-read'}   
        )
    file_url = f"{AWS_ENDPOINT_URL}/{'productos'}/{image.filename}"

    # Eliminar el archivo temporal
    os.remove(temp_file_path)

    # Insertar los detalles del producto en la base de datos
    cursor = connection.cursor()
    cursor.execute("INSERT INTO data (name, photo, precio, category, largo, ancho) VALUES (%s, %s, %s, %s, %s, %s)",
                   (name, file_url, price, category, largo, ancho))
    connection.commit()
    cursor.close()

    return {"message": "Item created successfully", "image_url": file_url}

# Endpoint para obtener un elemento por ID
@app.get("/items/{item_id}")
async def read_item(item_id: int):
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM data WHERE id = %s", (item_id,))
    item = cursor.fetchone()
    cursor.close()
    if item:
        return item
    else:
        raise HTTPException(status_code=404, detail="Item not found")

# Endpoint para obtener una lista de elementos con paginación
@app.get("/items/")
async def read_items(page: int = 1, limit: int = Query(10, gt=0)):
    offset = (page - 1) * limit
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM data LIMIT %s OFFSET %s", (limit, offset))
    items = cursor.fetchall()
    cursor.close()
    return items

# Endpoint para obtener una lista de cilindros con paginación
@app.get("/cilindros/")
async def read_items(page: int = 1, limit: int = Query(100, gt=0)):
    offset = (page - 1) * limit
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM cilindros LIMIT %s OFFSET %s", (limit, offset))
    items = cursor.fetchall()
    cursor.close()
    return items

# Endpoint para obtener una lista de elementos por categoría
@app.get("/items/category/{category}")
async def read_items_by_category(category: str):
    cursor = connection.cursor()
    query = "SELECT * FROM data WHERE category = %s"
    cursor.execute(query, (category,))
    items = cursor.fetchall()
    cursor.close()
    if items:
        return items
    else:
        raise HTTPException(status_code=404, detail="No items found in this category")

# Endpoint para obtener una lista de categorías
@app.get("/categories/")
async def read_categories():
    cursor = connection.cursor()
    cursor.execute("SELECT DISTINCT category FROM data")
    categories = cursor.fetchall()
    cursor.close()
    return [category[0] for category in categories]

# Endpoint para actualizar un elemento por ID
@app.put("/items/{item_id}")
async def update_item(
    item_id: int,
    name: str = Form(...),
    price: float = Form(...),
    category: str = Form(),
    image: UploadFile = File(None),  # Permitir que image sea None
    largo: float = Form(...),
    ancho: float = Form(...)
):
    file_url = None  # Inicializa la URL de la imagen como None

    # Comprueba si se proporcionó una nueva imagen
    if image is not None and image.filename:
        # Guardar temporalmente el archivo en el servidor
        temp_file_path = f"temp_{image.filename}"
        async with aiofiles.open(temp_file_path, 'wb') as out_file:
            content = await image.read()
            await out_file.write(content)

        # Subir el archivo a Digital Ocean Spaces
        with open(temp_file_path, 'rb') as file_data:
            client.upload_fileobj(
                Fileobj=file_data,
                Bucket="productos",
                Key=image.filename,
                ExtraArgs={'ACL': 'public-read'}
            )
        file_url = f"{AWS_ENDPOINT_URL}/{'productos'}/{image.filename}"

        # Eliminar el archivo temporal
        os.remove(temp_file_path)

    # Actualizar detalles del producto en la base de datos
    cursor = connection.cursor()
    cursor.execute(
        "UPDATE data SET name = %s, precio = %s, category = %s, largo = %s, ancho = %s WHERE id = %s",
        (name, price, category, largo, ancho, item_id)
    )
    if file_url is not None:
        cursor.execute(
            "UPDATE data SET photo = %s WHERE id = %s",
            (file_url, item_id)
        )
    updated_rows = cursor.rowcount
    connection.commit()
    cursor.close()

    if updated_rows == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"message": "Item updated successfully"}

# Endpoint para crear un pedido en Shopify
@app.post("/create_shopify_order/")
async def create_shopify_order(product_list: ProductListCheck, current_user: User = Depends(get_current_user)):
    cursor = connection.cursor()
    error_products = []
    total_price = 0
    product_counts = {}

    # Procesamiento de los productos
    for product in product_list.productos:
        cursor.execute("SELECT precio, name FROM data WHERE id = %s", (product.id,))
        result = cursor.fetchone()

        if result:
            precio_unitario_real, product_name = result
            precio_total_real = float(precio_unitario_real) * product.quantity
            total_price += precio_total_real
            product_counts[product_name] = product_counts.get(product_name, 0) + product.quantity

            if precio_total_real != product.price:
                error_products.append({"id": product.id, "expected_price": precio_total_real, "given_price": product.price})
        else:
            error_products.append({"id": product.id, "error": "Producto no encontrado"})

    cursor.close()

    if error_products:
        return {"error": "Hay discrepancias en los precios", "details": error_products}

    # Procesamiento de la imagen en base64
    shopify_images = []
    if product_list.imagen:
        base64_image = product_list.imagen.split(",")[1]
        shopify_images.append({"attachment": base64_image})

    # Seleccionar el producto con mayor cantidad y un adjetivo al azar
    max_product = max(product_counts, key=product_counts.get)
    random_adjective = random.choice(adjetivos_sabor_premium)
    title = f"Torre {max_product} {random_adjective}"

    # Crear un producto en Shopify
    shopify_product = {
        "product": {
            "title": title,
            "body_html": "<h1>Detalles:</h1>" + "<br>".join([f"{name}: {count}" for name, count in product_counts.items()]) +
                         f"<br><b>Precio Total:</b> ${total_price:.2f}",
            "vendor": "Torres de dulces",
            "product_type": "Torre",
            "status": "active",
            "images": shopify_images
        }
    }

    response = requests.post(
        f"https://{SHOPIFY_STORE_NAME}.myshopify.com/admin/api/2023-10/products.json",
        headers={"X-Shopify-Access-Token": SHOPIFY_API_TOKEN, "Content-Type": "application/json"},
        data=json.dumps(shopify_product)
    )

    if response.status_code != 201:
        raise HTTPException(status_code=response.status_code, detail=response.text)

    return response.json()

# .token
""""
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}
"""


# Ejecución del Servidor (esto no se ejecutará si importas este archivo como un módulo)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
