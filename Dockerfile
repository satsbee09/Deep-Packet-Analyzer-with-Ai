FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    build-essential \
    cmake \
    libpcap-dev

WORKDIR /app

COPY . .

RUN python3 -m pip install --break-system-packages -r backend/requirements.txt

RUN mkdir -p build && \
    cd build && \
    cmake .. && \
    cmake --build .

WORKDIR /app/backend

CMD ["python3", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "10000"]