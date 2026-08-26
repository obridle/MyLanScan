# Linux build for MyLanScan (PyInstaller one-file).
# Uses Debian's system Python because official python:*-slim images are built
# WITHOUT tkinter, and tkinter is required by customtkinter.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-tk python3-pip \
        libpython3.11 gcc libc6-dev binutils \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m pip install --no-cache-dir --break-system-packages \
        customtkinter zeroconf pyinstaller

WORKDIR /build
COPY Sample/ Sample/
RUN pyinstaller \
        --onefile \
        --name MyLanScan \
        --add-data "Sample/oui.json:." \
        --collect-all customtkinter \
        --noconfirm \
        Sample/S1mvp.py

# Result: /build/dist/MyLanScan  (self-contained Linux executable)
CMD ["/bin/true"]