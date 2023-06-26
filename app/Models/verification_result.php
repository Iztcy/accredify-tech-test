<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class verification_result extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id',
        'file_type',
        'verification_result',
    ];
}
