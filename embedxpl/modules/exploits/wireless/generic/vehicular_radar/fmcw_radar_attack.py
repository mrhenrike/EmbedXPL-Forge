"""FMCW Automotive Radar Physical Layer Attack Module.

Documents and provides reference implementation for attacks against
FMCW (Frequency Modulated Continuous Wave) automotive radars.

Based on academic research:
- MadRadar (Komari et al., NDSS 2024) - spoofing attack
- mmSpoof (Ranganathan et al., S&P 2023) - ghost object injection
- GHOSTRADAR framework

PREREQ HW: USRP/HackRF + mmWave amplifier + directional antenna
           (24 GHz or 77 GHz depending on target)

WARNING: Active radar jamming/spoofing is illegal in most jurisdictions
         without explicit authorization. Use only in controlled RF environments.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class FMCWRadarTarget:
    """Represents a phantom radar target to inject.

    Attributes:
        distance_m: Distance in meters from radar.
        velocity_kmh: Relative velocity in km/h (positive = approaching).
        angle_deg: Horizontal angle in degrees (-90 to +90).
        rcs_dbm2: Radar Cross Section in dBm^2 (larger = more visible).
    """

    distance_m: float = 20.0
    velocity_kmh: float = 0.0
    angle_deg: float = 0.0
    rcs_dbm2: float = 10.0


@dataclass
class FMCWRadarParams:
    """FMCW radar waveform parameters.

    Attributes:
        center_freq_ghz: Center frequency in GHz (24.1 or 76-77 GHz).
        bandwidth_mhz: Sweep bandwidth in MHz.
        sweep_time_ms: Chirp duration in milliseconds.
        num_chirps: Number of chirps per frame.
    """

    center_freq_ghz: float = 24.1
    bandwidth_mhz: float = 200.0
    sweep_time_ms: float = 2.0
    num_chirps: int = 128

    @property
    def range_resolution_m(self) -> float:
        """Calculate range resolution in meters.

        Returns:
            Range resolution in meters.
        """
        c = 3e8  # speed of light
        return c / (2 * self.bandwidth_mhz * 1e6)

    @property
    def max_range_m(self) -> float:
        """Calculate maximum unambiguous range.

        Returns:
            Maximum range in meters.
        """
        c = 3e8
        slope = self.bandwidth_mhz * 1e6 / (self.sweep_time_ms * 1e-3)
        return c * slope / (2 * slope)

    @property
    def velocity_resolution_mps(self) -> float:
        """Calculate velocity resolution in m/s.

        Returns:
            Velocity resolution in meters per second.
        """
        c = 3e8
        frame_time = self.num_chirps * self.sweep_time_ms * 1e-3
        return c / (2 * self.center_freq_ghz * 1e9 * frame_time)


class FMCWRadarAttackInfo:
    """Information about FMCW radar attack techniques.

    This class documents the attack vectors for FMCW automotive radars
    as described in academic literature. Active execution requires
    specialized hardware (USRP, mmWave components).

    Attributes:
        __info__: Module metadata.
    """

    __info__ = {
        "name": "FMCW Automotive Radar Physical Layer Attack",
        "category": "vehicular_radar",
        "type": "physical_layer",
        "frequencies": ["24 GHz ISM (automotive)", "76-77 GHz mmWave (automotive)"],
        "attack_types": [
            "False target injection (ghost objects)",
            "Target masking (hide real objects)",
            "Velocity spoofing",
            "Distance spoofing",
        ],
        "hw_req": [
            "USRP X310/B210 with UBX-40 daughter board (for 24 GHz)",
            "For 77 GHz: custom mmWave front-end + PA + LNA",
            "Directional horn antenna",
            "RF amplifier (> 20 dBm output)",
            "Low phase noise LO source",
        ],
        "legal_warning": (
            "Active radar spoofing/jamming is illegal without authorization. "
            "Causes safety hazard to vehicle occupants and road users. "
            "For use ONLY in shielded anechoic chambers or authorized test tracks."
        ),
        "references": [
            "MadRadar: NDSS 2024 - Komari et al.",
            "mmSpoof: IEEE S&P 2023 - Ranganathan et al.",
            "GHOSTRADAR: arxiv.org/abs/2207.05623",
            "Park et al., 'White-Stingray: Evaluating IMSI Catchers Detection'",
        ],
        "attack_description": {
            "false_positive": (
                "Transmit delayed/frequency-shifted version of received chirp "
                "to create phantom object at specific range/velocity. "
                "The radar sees a ghost car that doesn't exist."
            ),
            "false_negative": (
                "Transmit inverted signal to cancel real target reflections, "
                "hiding real objects from the radar."
            ),
            "translation": (
                "Shift the apparent position of real objects by transmitting "
                "time-delayed replicas of their radar echoes."
            ),
        },
    }


def calculate_beat_frequency(
    distance_m: float,
    radar_params: FMCWRadarParams,
) -> float:
    """Calculate the IF beat frequency for a target at given distance.

    Args:
        distance_m: Target distance in meters.
        radar_params: FMCW waveform parameters.

    Returns:
        Beat frequency in Hz.
    """
    c = 3e8
    slope = (radar_params.bandwidth_mhz * 1e6) / (radar_params.sweep_time_ms * 1e-3)
    return (2 * distance_m * slope) / c


def calculate_doppler_shift(
    velocity_mps: float,
    radar_params: FMCWRadarParams,
) -> float:
    """Calculate Doppler frequency shift for a moving target.

    Args:
        velocity_mps: Target velocity in m/s (positive = approaching).
        radar_params: FMCW waveform parameters.

    Returns:
        Doppler shift in Hz.
    """
    c = 3e8
    return (2 * velocity_mps * radar_params.center_freq_ghz * 1e9) / c


def compute_spoof_delay_ns(
    real_distance_m: float,
    fake_distance_m: float,
) -> float:
    """Compute delay needed to spoof a target at different distance.

    Args:
        real_distance_m: Real target distance in meters.
        fake_distance_m: Desired spoofed distance in meters.

    Returns:
        Required signal delay in nanoseconds.
    """
    c = 3e8
    real_delay = (2 * real_distance_m) / c
    fake_delay = (2 * fake_distance_m) / c
    return (fake_delay - real_delay) * 1e9


def run(
    target: Optional[FMCWRadarTarget] = None,
    radar: Optional[FMCWRadarParams] = None,
) -> dict:
    """Generate FMCW radar spoof parameters and return summary.

    This is a calculation/planning function. Actual transmission requires
    GNU Radio flowgraph on USRP/HackRF hardware.

    Args:
        target: Phantom target definition (defaults to 20 m ahead at 0 km/h).
        radar: FMCW radar waveform params (defaults to 24 GHz ISM band).

    Returns:
        Spoof parameter dict including beat frequency, delay, and SDR config.
    """
    _target = target or FMCWRadarTarget()
    _radar = radar or FMCWRadarParams()
    params = generate_spoof_parameters(_target, _radar)
    params["simulate"] = True
    params["warning"] = (
        "Active radar spoofing requires hardware and authorization. "
        "This output describes signal parameters only."
    )
    return params


def generate_spoof_parameters(
    target: FMCWRadarTarget,
    radar: FMCWRadarParams,
) -> dict:
    """Generate spoof signal parameters for SDR transmission.

    Calculates the required signal parameters to inject a phantom
    target at the specified range, velocity, and angle.

    Args:
        target: Phantom target to create.
        radar: FMCW radar waveform parameters.

    Returns:
        Dict with SDR transmission parameters.
    """
    beat_freq = calculate_beat_frequency(target.distance_m, radar)
    doppler = calculate_doppler_shift(target.velocity_kmh / 3.6, radar)

    return {
        "target": {
            "distance_m": target.distance_m,
            "velocity_kmh": target.velocity_kmh,
            "angle_deg": target.angle_deg,
        },
        "radar_params": {
            "center_freq_ghz": radar.center_freq_ghz,
            "bandwidth_mhz": radar.bandwidth_mhz,
            "sweep_time_ms": radar.sweep_time_ms,
        },
        "spoof_signal": {
            "beat_frequency_hz": beat_freq,
            "doppler_shift_hz": doppler,
            "total_if_freq_hz": beat_freq + doppler,
            "required_delay_ns": (2 * target.distance_m) / 3e8 * 1e9,
            "tx_power_note": (
                f"Power must exceed target RCS ({target.rcs_dbm2} dBm^2) "
                "at receiver after path loss"
            ),
        },
        "hw_implementation": {
            "approach": "MadRadar/mmSpoof: receive chirp, delay by required_delay_ns, retransmit",
            "usrp_sample_rate_mhz": radar.bandwidth_mhz * 2,
            "antenna": f"Directional at {target.angle_deg} degrees",
            "note": (
                "Full implementation requires GNU Radio flowgraph with "
                "USRP source/sink and custom delay/frequency shift block"
            ),
        },
    }
