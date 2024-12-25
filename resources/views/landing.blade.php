<x-guest-layout>
    <div class="min-h-screen relative">
        <!-- Background Image with Overlay -->
        <div class="absolute inset-0 z-0">
            <img src="{{ asset('img/background.png') }}" alt="Background" class="w-full h-full object-cover object-center bg-center bg-no-repeat" style="object-position: 50% 20%;">
            <div class="absolute inset-0 bg-gradient-to-b from-[#E3F2F9]/60 via-[#E3F2F9]/40 to-white/90"></div>
        </div>
        
        <!-- Content Container -->
        <div class="relative z-10 backdrop-blur-[2px]">

        <!-- Navbar -->
        <nav class="bg-white/80 backdrop-blur-md fixed w-full z-50 shadow-sm">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="flex justify-between h-16">
                    <div class="flex items-center">
                        <div class="shrink-0 flex items-center">
                            <a href="/" class="flex items-center">
                                <span class="ml-2 text-xl font-bold text-[#00B4D8]">Laundry On</span>
                            </a>
                        </div>
                    </div>

                    <!-- Desktop Navigation -->
                    <div class="hidden sm:flex sm:items-center sm:ml-6 space-x-8">
                        <a href="#home" class="text-gray-600 hover:text-[#00B4D8] transition-colors duration-200">Home</a>
                        <a href="#layanan" class="text-gray-600 hover:text-[#00B4D8] transition-colors duration-200">Layanan</a>
                        <a href="#keunggulan" class="text-gray-600 hover:text-[#00B4D8] transition-colors duration-200">Keunggulan</a>
                        <a href="#tentang" class="text-gray-600 hover:text-[#00B4D8] transition-colors duration-200">Tentang</a>
                        
                        <!-- Auth Buttons -->
                        <div class="flex items-center space-x-4">
                            <a href="{{ route('login') }}" class="text-[#00B4D8] hover:text-[#0096B4] font-semibold transition-colors duration-200">
                                Masuk
                            </a>
                            <a href="{{ route('register') }}" class="inline-flex items-center px-4 py-2 bg-[#00B4D8] border border-transparent rounded-lg font-semibold text-xs text-white uppercase tracking-widest hover:bg-[#0096B4] transform hover:scale-[1.02] transition-all duration-200">
                                Daftar
                            </a>
                        </div>
                    </div>

                    <!-- Mobile menu button -->
                    <div class="flex items-center sm:hidden">
                        <button type="button" class="mobile-menu-button inline-flex items-center justify-center p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-[#00B4D8]" aria-controls="mobile-menu" aria-expanded="false">
                            <svg class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
                            </svg>
                        </button>
                    </div>
                </div>

                <!-- Mobile Navigation Menu -->
                <div class="sm:hidden hidden" id="mobile-menu">
                    <div class="pt-2 pb-3 space-y-1">
                        <a href="#home" class="block px-3 py-2 text-base font-medium text-gray-600 hover:text-[#00B4D8] hover:bg-gray-50 transition-colors duration-200">Home</a>
                        <a href="#layanan" class="block px-3 py-2 text-base font-medium text-gray-600 hover:text-[#00B4D8] hover:bg-gray-50 transition-colors duration-200">Layanan</a>
                        <a href="#keunggulan" class="block px-3 py-2 text-base font-medium text-gray-600 hover:text-[#00B4D8] hover:bg-gray-50 transition-colors duration-200">Keunggulan</a>
                        <a href="#tentang" class="block px-3 py-2 text-base font-medium text-gray-600 hover:text-[#00B4D8] hover:bg-gray-50 transition-colors duration-200">Tentang</a>
                        <div class="pt-4 pb-3 border-t border-gray-200">
                            <div class="flex items-center px-4 space-x-3">
                                <a href="{{ route('login') }}" class="text-[#00B4D8] hover:text-[#0096B4] font-semibold transition-colors duration-200">
                                    Masuk
                                </a>
                                <a href="{{ route('register') }}" class="inline-flex items-center px-4 py-2 bg-[#00B4D8] border border-transparent rounded-lg font-semibold text-xs text-white uppercase tracking-widest hover:bg-[#0096B4] transform hover:scale-[1.02] transition-all duration-200">
                                    Daftar
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </nav>

        <!-- Hero Section -->
        <section id="home" class="pt-24 relative overflow-hidden">
            <!-- Background Patterns -->
            <div class="absolute inset-0 opacity-5">
                <div class="absolute top-0 left-0 w-96 h-96 bg-[#00B4D8] rounded-full mix-blend-multiply filter blur-3xl animate-blob"></div>
                <div class="absolute top-0 right-0 w-96 h-96 bg-[#0096B4] rounded-full mix-blend-multiply filter blur-3xl animate-blob animation-delay-2000"></div>
                <div class="absolute bottom-0 left-1/2 w-96 h-96 bg-[#00B4D8] rounded-full mix-blend-multiply filter blur-3xl animate-blob animation-delay-4000"></div>
            </div>

            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
                <div class="lg:flex lg:items-center lg:justify-between">
                    <div class="lg:w-1/2 space-y-6">
                        <h1 class="text-4xl font-bold text-gray-900 sm:text-5xl leading-tight">
                            Laundry On <br>
                            <span class="text-[#00B4D8] animate-text bg-gradient-to-r from-[#00B4D8] via-[#0096B4] to-[#00B4D8] bg-clip-text text-transparent">Cepat & Berkualitas</span>
                        </h1>
                        <p class="mt-4 text-xl text-gray-600 leading-relaxed">
                        Laundry On Yogyakarta.
                        Kualitas nomor satu! Kami menggunakan detergen dan pelembut terbaik yang aman untuk pakaianmu. 
                        Dijamin wangi tahan lama dan bersih menyeluruh. Yuk, coba layanan premium kami!
                        </p>
                        <div class="mt-8 flex gap-x-4">
                            <a href="#layanan" class="group inline-flex items-center px-6 py-3 border-2 border-[#00B4D8] rounded-lg font-semibold text-[#00B4D8] hover:bg-[#00B4D8] hover:text-white transform hover:scale-[1.02] transition-all duration-200">
                                Lihat Layanan
                                <svg class="ml-2 -mr-1 w-5 h-5 group-hover:translate-x-1 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
                                </svg>
                            </a>
                        </div>
                    </div>
                    <div class="mt-8 lg:mt-0 lg:w-1/2">
                        <img src="{{ asset('img/icon.png') }}" alt="Laundry Illustration" class="w-1/2 h-auto animate-float mx-auto">
                    </div>
                </div>
            </div>
        </section>

        <!-- Features Section -->
        <section id="keunggulan" class="py-16 bg-white/80 backdrop-blur-sm">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="text-center">
                    <h2 class="text-3xl font-bold text-gray-900">Keunggulan Kami</h2>
                    <div class="w-20 h-1 bg-[#00B4D8] mx-auto mt-4 mb-8"></div>
                    <p class="mt-4 text-xl text-gray-600">Mengapa harus memilih Laundry On?</p>
                </div>

                <div class="mt-12 grid grid-cols-1 gap-8 sm:grid-cols-2 lg:grid-cols-3">
                    <!-- Feature 1 -->
                    <div class="bg-white rounded-xl p-8 shadow-soft hover:shadow-md transition-all duration-300 transform hover:-translate-y-1">
                        <div class="inline-block p-4 bg-[#00B4D8]/10 rounded-lg mb-4">
                            <svg class="w-8 h-8 text-[#00B4D8]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                        </div>
                        <h3 class="text-xl font-semibold text-gray-900 mb-2">Express Service</h3>
                        <p class="text-gray-600">Layanan kilat mulai dari 3 jam selesai dengan hasil maksimal</p>
                    </div>

                    <!-- Feature 2 -->
                    <div class="bg-white rounded-xl p-8 shadow-soft hover:shadow-md transition-all duration-300 transform hover:-translate-y-1">
                        <div class="inline-block p-4 bg-[#00B4D8]/10 rounded-lg mb-4">
                            <svg class="w-8 h-8 text-[#00B4D8]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                        </div>
                        <h3 class="text-xl font-semibold text-gray-900 mb-2">Kualitas Terjamin</h3>
                        <p class="text-gray-600">Menggunakan deterjen premium dan teknik pencucian profesional</p>
                    </div>

                    <!-- Feature 3 -->
                    <div class="bg-white rounded-xl p-8 shadow-soft hover:shadow-md transition-all duration-300 transform hover:-translate-y-1">
                        <div class="inline-block p-4 bg-[#00B4D8]/10 rounded-lg mb-4">
                            <svg class="w-8 h-8 text-[#00B4D8]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                            </svg>
                        </div>
                        <h3 class="text-xl font-semibold text-gray-900 mb-2">Staff Profesional</h3>
                        <p class="text-gray-600">Tim kami terlatih untuk memberikan pelayanan terbaik</p>
                    </div>
                </div>
            </div>
        </section>

        <!-- Services Section -->
        <section id="layanan" class="py-16 bg-gradient-to-b from-[#E3F2F9] to-white relative overflow-hidden">
            <div class="absolute inset-0 opacity-10">
                <div class="absolute top-0 right-0 w-96 h-96 bg-[#00B4D8] rounded-full mix-blend-multiply filter blur-3xl animate-blob"></div>
                <div class="absolute bottom-0 left-0 w-96 h-96 bg-[#0096B4] rounded-full mix-blend-multiply filter blur-3xl animate-blob animation-delay-2000"></div>
            </div>

            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="text-center">
                    <h2 class="text-3xl font-bold text-gray-900">Layanan Kami</h2>
                    <div class="w-20 h-1 bg-[#00B4D8] mx-auto mt-4 mb-8"></div>
                    <p class="mt-4 text-xl text-gray-600">Pilih layanan terbaik sesuai kebutuhan Anda</p>
                </div>

                <div class="mt-12 grid grid-cols-1 gap-8 sm:grid-cols-2 lg:grid-cols-3">
                    @foreach($services as $service)
                    <div class="bg-white rounded-2xl shadow-soft hover:shadow-md transition-all duration-300 transform hover:-translate-y-1 overflow-hidden">
                        <div class="p-8">
                            <div class="text-center mb-6">
                                <span class="inline-block p-3 rounded-full bg-[#00B4D8]/10 text-[#00B4D8]">
                                    <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                                    </svg>
                                </span>
                            </div>
                            <h3 class="text-xl font-bold text-center text-gray-900 mb-2">{{ $service->name }}</h3>
                            <p class="text-gray-600 text-center mb-4">{{ $service->description }}</p>
                            <div class="text-center">
                                <span class="text-2xl font-bold text-[#00B4D8]">Rp {{ number_format($service->price_per_kg, 0, ',', '.') }}</span>
                                <span class="text-gray-500">/kg</span>
                            </div>
                        </div>
                    </div>
                    @endforeach
                </div>
            </div>
        </section>

        <!-- About Section -->
        <section id="tentang" class="py-16 bg-white/80 backdrop-blur-sm">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="lg:flex lg:items-center lg:justify-between gap-12">
                    <div class="lg:w-1/2 mb-10 lg:mb-0">
                        <img src="{{ asset('img/icon.png') }}" alt="Tentang Laundry On" class="rounded-2xl shadow-lg w-1/2 h-auto object-cover transform hover:scale-[1.02] transition-transform duration-300 mx-auto">
                    </div>
                    <div class="lg:w-1/2 space-y-6">
                        <h2 class="text-3xl font-bold text-gray-900">Tentang Laundry On</h2>
                        <div class="w-20 h-1 bg-[#00B4D8]"></div>
                        <p class="text-xl text-gray-600 leading-relaxed">
                            Laundry On adalah penyedia jasa laundry premium yang telah berpengalaman melayani pelanggan sejak tahun 2020. 
                            Kami berkomitmen untuk memberikan pelayanan laundry terbaik dengan standar kualitas tinggi.
                        </p>
                        <div class="grid grid-cols-2 gap-6 mt-8">
                            <div class="text-center p-6 bg-gray-50 rounded-xl hover:shadow-md transition-all duration-300">
                                <h4 class="text-3xl font-bold text-[#00B4D8] animate-pulse">1000+</h4>
                                <p class="text-gray-600 mt-2">Pelanggan Puas</p>
                            </div>
                            <div class="text-center p-6 bg-gray-50 rounded-xl hover:shadow-md transition-all duration-300">
                                <h4 class="text-3xl font-bold text-[#00B4D8] animate-pulse">24/7</h4>
                                <p class="text-gray-600 mt-2">Layanan Express</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Developer Team Section -->
                <div class="mt-20">
                    <h2 class="text-3xl font-bold text-gray-900 text-center">Tim Developer</h2>
                    <div class="w-20 h-1 bg-[#00B4D8] mx-auto mt-4 mb-8"></div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8 mt-12">
                        <!-- Developer 1 -->
                        <div class="bg-white p-6 rounded-xl shadow-soft hover:shadow-md transition-all duration-300 transform hover:-translate-y-1">
                            <div class="text-center">
                                <div class="w-24 h-24 mx-auto mb-4 overflow-hidden rounded-full ring-4 ring-[#00B4D8]/20">
                                    <img src="{{ asset('img/khent.jpg') }}" alt="Khent Harianto" class="w-full h-full object-cover hover:scale-110 transition-transform duration-300">
                                </div>
                                <h3 class="text-xl font-bold text-gray-900">Khent Harianto Sandang</h3>
                                <p class="text-[#00B4D8] font-medium">Full Stack Developer</p>
                                <p class="text-gray-600 mt-2">22.83.0834</p>
                            </div>
                        </div>

                        <!-- Developer 2 -->
                        <div class="bg-white p-6 rounded-xl shadow-soft hover:shadow-md transition-all duration-300 transform hover:-translate-y-1">
                            <div class="text-center">
                                <div class="w-24 h-24 mx-auto mb-4 overflow-hidden rounded-full ring-4 ring-[#00B4D8]/20">
                                    <img src="{{ asset('img/adit.jpg') }}" alt="Daffa Syafiq" class="w-full h-full object-cover hover:scale-110 transition-transform duration-300">
                                </div>
                                <h3 class="text-xl font-bold text-gray-900">Aditya Rosprihananta</h3>
                                <p class="text-[#00B4D8] font-medium">Backend Developer</p>
                                <p class="text-gray-600 mt-2">22.83.0843</p>
                            </div>
                        </div>

                        <!-- Developer 3 -->
                        <div class="bg-white p-6 rounded-xl shadow-soft hover:shadow-md transition-all duration-300 transform hover:-translate-y-1">
                            <div class="text-center">
                                <div class="w-24 h-24 mx-auto mb-4 overflow-hidden rounded-full ring-4 ring-[#00B4D8]/20">
                                    <img src="{{ asset('img/dian.jpg') }}" alt="Dimas Bagus" class="w-full h-full object-cover hover:scale-110 transition-transform duration-300">
                                </div>
                                <h3 class="text-xl font-bold text-gray-900">Dian Andrian</h3>
                                <p class="text-[#00B4D8] font-medium">Deployment</p>
                                <p class="text-gray-600 mt-2">22.83.0881</p>
                            </div>
                        </div>

                        <!-- Developer 4 -->
                        <div class="bg-white p-6 rounded-xl shadow-soft hover:shadow-md transition-all duration-300 transform hover:-translate-y-1">
                            <div class="text-center">
                                <div class="w-24 h-24 mx-auto mb-4 overflow-hidden rounded-full ring-4 ring-[#00B4D8]/20">
                                    <img src="{{ asset('img/majid.jpg') }}" alt="Dimas Dwi" class="w-full h-full object-cover hover:scale-110 transition-transform duration-300">
                                </div>
                                <h3 class="text-xl font-bold text-gray-900">Muhammad Ahnaf Maajid</h3>
                                <p class="text-[#00B4D8] font-medium">UI/UX Designer</p>
                                <p class="text-gray-600 mt-2">22.83.0884</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- Footer -->
        <footer class="bg-white/90 backdrop-blur-sm border-t border-gray-100">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
                <div class="grid grid-cols-1 md:grid-cols-4 gap-8">
                    <div class="col-span-2">
                        <div class="flex items-center mb-4">
                            <img src="{{ asset('img/Logo.png') }}" alt="Logo" class="h-10 w-10">
                            <span class="ml-2 text-xl font-bold text-[#00B4D8]">Laundry On</span>
                        </div>
                        <p class="text-gray-600 mb-4">
                            Solusi laundry terbaik untuk Anda dengan layanan express dan kualitas premium.
                        </p>
                    </div>
                    <div>
                        <h3 class="text-gray-900 font-semibold mb-4">Layanan</h3>
                        <ul class="space-y-2">
                            <li><a href="#" class="text-gray-600 hover:text-[#00B4D8] transition-colors duration-200">Kilat 1 Hari</a></li>
                            <li><a href="#" class="text-gray-600 hover:text-[#00B4D8] transition-colors duration-200">FastHand 2 Hari</a></li>
                            <li><a href="#" class="text-gray-600 hover:text-[#00B4D8] transition-colors duration-200">Slowhand 4 Hari</a></li>
                        </ul>
                    </div>
                    <div>
                        <h3 class="text-gray-900 font-semibold mb-4">Kontak</h3>
                        <ul class="space-y-2">
                            <li class="flex items-center text-gray-600 hover:text-[#00B4D8] transition-colors duration-200">
                                <svg class="w-5 h-5 mr-2 text-[#00B4D8]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z" />
                                </svg>
                                +62 812-3456-7890
                            </li>
                            <li class="flex items-center text-gray-600 hover:text-[#00B4D8] transition-colors duration-200">
                                <svg class="w-5 h-5 mr-2 text-[#00B4D8]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                                </svg>
                                info@laundryon.com
                            </li>
                        </ul>
                    </div>
                </div>
                <div class="mt-8 pt-8 border-t border-gray-100">
                    <div class="text-center">
                        <p class="text-gray-600">2024 © Laundry On. All rights reserved.</p>
                    </div>
                </div>
            </div>
        </footer>

        </div>
    </div>

    <!-- Add animations -->
    <style>
        @keyframes float {
            0% { transform: translateY(0px); }
            50% { transform: translateY(-10px); }
            100% { transform: translateY(0px); }
        }
        .animate-float {
            animation: float 3s ease-in-out infinite;
        }
        @keyframes text {
            0%, 100% {
                background-size: 200% 200%;
                background-position: left center;
            }
            50% {
                background-size: 200% 200%;
                background-position: right center;
            }
        }
        .animate-text {
            animation: text 3s ease-in-out infinite;
        }
        @keyframes blob {
            0% {
                transform: translate(0px, 0px) scale(1);
            }
            33% {
                transform: translate(30px, -50px) scale(1.1);
            }
            66% {
                transform: translate(-20px, 20px) scale(0.9);
            }
            100% {
                transform: translate(0px, 0px) scale(1);
            }
        }
        .animate-blob {
            animation: blob 7s infinite;
        }
        .animation-delay-2000 {
            animation-delay: 2s;
        }
        .animation-delay-4000 {
            animation-delay: 4s;
        }
        .shadow-soft {
            box-shadow: 0 2px 15px rgba(0, 0, 0, 0.05);
        }
        /* Add background image styles */
        .bg-image {
            background-image: url('/img/background.png');
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
        }
    </style>

    <!-- JavaScript for Mobile Menu -->
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const mobileMenuButton = document.querySelector('.mobile-menu-button');
            const mobileMenu = document.getElementById('mobile-menu');

            mobileMenuButton.addEventListener('click', function() {
                mobileMenu.classList.toggle('hidden');
            });

            // Smooth scroll for anchor links
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                anchor.addEventListener('click', function (e) {
                    e.preventDefault();
                    document.querySelector(this.getAttribute('href')).scrollIntoView({
                        behavior: 'smooth'
                    });
                });
            });
        });
    </script>
</x-guest-layout> 