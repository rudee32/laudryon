@php
use Illuminate\Support\Facades\Route;
@endphp

<x-guest-layout>
    <div class="min-h-screen flex flex-col items-center justify-center bg-gradient-to-br from-[#F8FAFC] to-[#E2E8F0]">
        <!-- Login Card -->
        <div class="w-full max-w-4xl bg-white shadow-[0_8px_30px_rgb(0,0,0,0.08)] rounded-2xl flex overflow-hidden">
            <!-- Left Side - Logo & Title -->
            <div class="w-1/2 bg-[#00B4D8] p-12 flex flex-col items-center justify-center text-white relative overflow-hidden">
                <!-- Background Pattern -->
                <div class="absolute inset-0 opacity-10">
                    <div class="absolute inset-0 bg-pattern transform rotate-45"></div>
                </div>
                
                <!-- Content -->
                <div class="relative z-10 text-center">
                    <img src="{{ asset('img/Logo.png') }}" alt="Logo" class="h-80 w-80 object-contain mb-4 animate-float">
                    <h1 class="text-3xl font-bold mb-2">Laundry On</h1>
                    <p class="text-lg text-white/90">
                        Solusi laundry terbaik untuk Anda
                    </p>
                    <p class="mt-4 text-sm text-white/80 max-w-sm mx-auto">
                        Selamat datang kembali! Silakan masuk untuk mengakses layanan kami.
                    </p>
                </div>
            </div>

            <!-- Right Side - Login Form -->
            <div class="w-1/2 p-12">
                <div class="mb-8">
                    <h2 class="text-2xl font-bold text-gray-900">Masuk</h2>
                    <p class="mt-2 text-gray-600">Masukkan email dan password Anda</p>
                </div>

                <form method="POST" action="{{ route('login') }}">
                    @csrf

                    <!-- Email Field -->
                    <div class="mb-6">
                        <label for="email" class="block text-sm font-medium text-gray-700 mb-2">Email</label>
                        <div class="relative">
                            <input 
                                type="email"
                                id="email"
                                name="email"
                                class="w-full px-4 py-3 rounded-lg border-2 border-gray-100 focus:border-[#00B4D8] focus:ring-0 transition-colors duration-200"
                                placeholder="Masukkan email Anda"
                                required
                                autofocus
                            >
                            <div class="absolute inset-y-0 right-4 flex items-center pointer-events-none">
                                <svg class="h-5 w-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 12a4 4 0 10-8 0 4 4 0 008 0zm0 0v1.5a2.5 2.5 0 005 0V12a9 9 0 10-9 9m4.5-1.206a8.959 8.959 0 01-4.5 1.207" />
                                </svg>
                            </div>
                        </div>
                    </div>

                    <!-- Password Field -->
                    <div class="mb-6">
                        <label for="password" class="block text-sm font-medium text-gray-700 mb-2">Password</label>
                        <div class="relative" x-data="{ show: false }">
                            <input 
                                :type="show ? 'text' : 'password'"
                                id="password"
                                name="password"
                                class="w-full px-4 py-3 rounded-lg border-2 border-gray-100 focus:border-[#00B4D8] focus:ring-0 transition-colors duration-200"
                                placeholder="Masukkan password Anda"
                                required
                            >
                            <button 
                                @click="show = !show" 
                                type="button"
                                class="absolute inset-y-0 right-4 flex items-center text-gray-400 hover:text-gray-600">
                                <svg x-show="!show" class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                                </svg>
                                <svg x-show="show" class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                                </svg>
                            </button>
                        </div>
                    </div>

                    <!-- Remember Me -->
                    <div class="flex items-center justify-between mb-6">
                        <label class="flex items-center">
                            <input type="checkbox" name="remember" class="rounded border-gray-300 text-[#00B4D8] focus:border-[#00B4D8] focus:ring-[#00B4D8]">
                            <span class="ml-2 text-sm text-gray-600">Ingat saya</span>
                        </label>
                    </div>

                    <!-- Submit Button -->
                    <button 
                        type="submit"
                        class="w-full py-3 bg-[#00B4D8] text-white rounded-lg font-medium hover:bg-[#0096B4] transform hover:scale-[1.02] transition-all duration-200">
                        Masuk
                    </button>

                    <!-- Error Messages -->
                    @if ($errors->any())
                        <div class="mt-4 text-sm text-red-500 text-center bg-red-50 rounded-lg py-2">
                            @foreach ($errors->all() as $error)
                                <p>{{ $error }}</p>
                            @endforeach
                        </div>
                    @endif

                    <!-- Register Link -->
                    <div class="mt-6 text-center">
                        <p class="text-sm text-gray-600">
                            Belum punya akun?
                            <a href="{{ route('register') }}" class="font-medium text-[#00B4D8] hover:text-[#0096B4] transition-colors duration-200">
                                Daftar sekarang
                            </a>
                        </p>
                    </div>

                    <!-- Copyright -->
                    <div class="mt-8 text-center">
                        <p class="text-xs text-gray-400">
                            2024 © Laundry On. All rights reserved.
                        </p>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Add floating animation -->
    <style>
        @keyframes float {
            0% { transform: translateY(0px); }
            50% { transform: translateY(-10px); }
            100% { transform: translateY(0px); }
        }
        .animate-float {
            animation: float 3s ease-in-out infinite;
        }
        .bg-pattern {
            background-image: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23fff' fill-opacity='0.4'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
        }
    </style>
</x-guest-layout>
