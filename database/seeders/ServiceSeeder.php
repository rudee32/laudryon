<?php

namespace Database\Seeders;

use App\Models\Service;
use Illuminate\Database\Seeder;
use Illuminate\Support\Carbon;

class ServiceSeeder extends Seeder
{
    public function run()
    {
        $now = Carbon::now();
        
        Service::create([
            'name' => 'Fast Hand',
            'price_per_kg' => 10000,
            'description' => 'Fasthand dan wangi',
            'estimated_time' => 'Estimasi 2 hari',
            'created_at' => $now,
            'updated_at' => $now
        ]);

        Service::create([
            'name' => 'Cuci Setrika',
            'price_per_kg' => 8000,
            'description' => 'Layanan cuci dan setrika regular',
            'estimated_time' => 'Estimasi 3 hari',
            'created_at' => $now,
            'updated_at' => $now
        ]);

        Service::create([
            'name' => 'Cuci Lipat',
            'price_per_kg' => 6000,
            'description' => 'Layanan cuci tanpa setrika',
            'estimated_time' => 'Estimasi 2 hari',
            'created_at' => $now,
            'updated_at' => $now
        ]);
    }
} 