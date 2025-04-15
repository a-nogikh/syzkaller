FROM debian:bookworm

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
	# Build essentials:
	gcc g++ binutils make ccache \
	# Some common utilities:
	unzip curl sudo procps psmisc nano vim git bzip2 dh-autoreconf software-properties-common \
	# These are needed to build Linux kernel:
	flex bison bc gawk dwarves cpio texinfo texi2html lzop lbzip2 \
	zlib1g-dev libelf-dev libncurses-dev libmpc-dev libssl-dev \
	apt-transport-https curl gnupg python-is-python3 \
	# Needed for CONFIG_GENDWARFKSYMS.
	libdw-dev

# Add llvm-20.

RUN apt-get install -y -q gnupg software-properties-common apt-transport-https
RUN curl https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN echo "deb http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-20 main" | sudo tee /etc/apt/sources.list.d/llvm-20.list
RUN apt-get update --allow-releaseinfo-change
RUN apt-get install -y -q --no-install-recommends llvm-20 clang-20 clang-format-20 clang-tidy-20 lld-20
RUN apt autoremove -y -q
RUN sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-20 100
RUN sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-20 100
RUN sudo update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-20 100
RUN sudo update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-20 100
RUN sudo update-alternatives --install /usr/bin/ld.lld ld.lld /usr/bin/lld-20 100
RUN sudo update-alternatives --install /usr/bin/llvm-nm llvm-nm /usr/bin/llvm-nm-20 100
RUN sudo update-alternatives --install /usr/bin/llvm-ar llvm-ar /usr/bin/llvm-ar-20 100
RUN sudo update-alternatives --install /usr/bin/llvm-objcopy llvm-objcopy /usr/bin/llvm-objcopy-20 100
RUN sudo update-alternatives --install /usr/bin/llvm-objdump llvm-objdump /usr/bin/llvm-objdump-20 100
RUN sudo update-alternatives --install /usr/bin/llvm-addr2line llvm-addr2line /usr/bin/llvm-addr2line-20 100
RUN sudo update-alternatives --install /usr/bin/llvm-readelf llvm-readelf /usr/bin/llvm-readelf-20 100
RUN sudo update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-20 100

# Add some rust.

ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
RUN rustup component add rust-src
RUN cargo install --locked bindgen-cli
