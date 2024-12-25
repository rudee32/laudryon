<?php

namespace App\Http\Controllers;

use App\Models\Order;
use App\Models\Customer;
use Illuminate\Http\Request;
use Carbon\Carbon;

class DashboardController extends Controller
{
    public function index()
    {
        // Hitung total pesanan
        $totalOrders = Order::count();

        // Hitung pesanan hari ini
        $todayOrders = Order::whereDate('created_at', Carbon::today())->count();

        // Hitung total pelanggan
        $totalCustomers = Customer::count();

        // Hitung pendapatan hari ini
        $todayIncome = Order::whereDate('created_at', Carbon::today())
            ->where('status', 'completed')
            ->sum('total_price');

        // Ambil pesanan terbaru
        $latestOrders = Order::with(['customer', 'service'])
            ->latest()
            ->take(5)
            ->get();

        return view('dashboard', compact(
            'totalOrders',
            'todayOrders',
            'totalCustomers',
            'todayIncome',
            'latestOrders'
        ));
    }
} 