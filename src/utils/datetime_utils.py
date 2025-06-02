"""
Date and time processing utilities using python-dateutil 2.8+ for comprehensive 
date parsing, timezone handling, and date manipulation operations.

Provides equivalent functionality to Node.js moment.js library with enhanced 
timezone support and enterprise-grade date processing capabilities.

This module implements:
- Date/time processing with python-dateutil 2.8+ equivalent to Node.js moment per Section 0.2.4
- Date/time formatting preserving ISO 8601 standards per Section 0.1.4 data exchange formats
- Timezone handling for enterprise applications per Section 5.4.1 cross-cutting concerns
- Date parsing and validation utilities for business logic processing per Section 5.2.4
"""

import re
from datetime import datetime, date, time, timedelta, timezone
from typing import Optional, Union, Any, Dict, List, Tuple
from decimal import Decimal

try:
    from dateutil import parser as dateutil_parser
    from dateutil import tz
    from dateutil.relativedelta import relativedelta
except ImportError as e:
    raise ImportError(
        "python-dateutil 2.8+ is required for datetime utilities. "
        "Install with: pip install python-dateutil>=2.8"
    ) from e


# Type aliases for better code readability
DateTimeInput = Union[datetime, date, str, int, float, None]
TimezoneInput = Union[str, timezone, tz.tzinfo.BaseTzInfo, None]


class DateTimeError(Exception):
    """Base exception for datetime processing errors."""
    pass


class DateParseError(DateTimeError):
    """Exception raised when date parsing fails."""
    pass


class TimezoneError(DateTimeError):
    """Exception raised for timezone-related errors."""
    pass


class DateValidationError(DateTimeError):
    """Exception raised for date validation errors."""
    pass


class DateTimeProcessor:
    """
    Enterprise-grade date and time processing class providing comprehensive
    date parsing, formatting, and manipulation capabilities equivalent to Node.js moment.js.
    
    Features:
    - ISO 8601 compliant date formatting for API compatibility
    - Timezone-aware date processing for enterprise applications
    - Comprehensive date parsing and validation
    - Business logic support utilities
    - Thread-safe operations
    """
    
    # Common date formats for parsing
    COMMON_FORMATS = [
        '%Y-%m-%d',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S%z',
        '%Y-%m-%d %H:%M:%S',
        '%m/%d/%Y',
        '%m-%d-%Y',
        '%d/%m/%Y',
        '%d-%m-%Y',
        '%B %d, %Y',
        '%b %d, %Y',
        '%Y-%m-%dT%H:%M:%S.%fZ',
        '%Y-%m-%dT%H:%M:%S.%f%z',
    ]
    
    # ISO 8601 format patterns
    ISO_8601_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
    ISO_8601_WITH_MS_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
    ISO_8601_LOCAL_FORMAT = '%Y-%m-%dT%H:%M:%S'
    
    def __init__(self, default_timezone: TimezoneInput = None):
        """
        Initialize DateTimeProcessor with optional default timezone.
        
        Args:
            default_timezone: Default timezone for operations (UTC if None)
        """
        self.default_timezone = self._normalize_timezone(default_timezone or timezone.utc)
    
    def _normalize_timezone(self, tz_input: TimezoneInput) -> timezone:
        """
        Normalize timezone input to a timezone object.
        
        Args:
            tz_input: Timezone input in various formats
            
        Returns:
            Normalized timezone object
            
        Raises:
            TimezoneError: If timezone cannot be normalized
        """
        if tz_input is None:
            return timezone.utc
        
        if isinstance(tz_input, timezone):
            return tz_input
        
        if hasattr(tz_input, 'tzinfo') and tz_input.tzinfo is not None:
            return tz_input.tzinfo
        
        if isinstance(tz_input, str):
            try:
                # Handle common timezone strings
                if tz_input.upper() == 'UTC':
                    return timezone.utc
                elif tz_input.upper() == 'LOCAL':
                    return tz.tzlocal()
                else:
                    # Try to parse as timezone name
                    parsed_tz = tz.gettz(tz_input)
                    if parsed_tz is not None:
                        return parsed_tz
                    else:
                        raise TimezoneError(f"Unknown timezone: {tz_input}")
            except Exception as e:
                raise TimezoneError(f"Failed to parse timezone '{tz_input}': {str(e)}") from e
        
        raise TimezoneError(f"Unsupported timezone type: {type(tz_input)}")
    
    def parse(self, date_input: DateTimeInput, timezone_input: TimezoneInput = None, 
              strict: bool = False) -> datetime:
        """
        Parse date input into a datetime object with comprehensive format support.
        
        Args:
            date_input: Date input in various formats (string, datetime, timestamp, etc.)
            timezone_input: Target timezone for the result
            strict: If True, raise exception on parse failure; if False, return current time
            
        Returns:
            Parsed datetime object
            
        Raises:
            DateParseError: If parsing fails and strict=True
        """
        if date_input is None:
            if strict:
                raise DateParseError("Cannot parse None date input")
            return self.now(timezone_input)
        
        target_tz = self._normalize_timezone(timezone_input or self.default_timezone)
        
        try:
            # Handle datetime objects
            if isinstance(date_input, datetime):
                if date_input.tzinfo is None:
                    return date_input.replace(tzinfo=target_tz)
                return date_input.astimezone(target_tz)
            
            # Handle date objects
            if isinstance(date_input, date):
                return datetime.combine(date_input, time.min).replace(tzinfo=target_tz)
            
            # Handle numeric timestamps
            if isinstance(date_input, (int, float, Decimal)):
                timestamp = float(date_input)
                # Handle both seconds and milliseconds timestamps
                if timestamp > 1e10:  # Milliseconds timestamp
                    timestamp /= 1000
                return datetime.fromtimestamp(timestamp, tz=target_tz)
            
            # Handle string input
            if isinstance(date_input, str):
                date_str = date_input.strip()
                
                # Handle empty string
                if not date_str:
                    if strict:
                        raise DateParseError("Cannot parse empty string")
                    return self.now(timezone_input)
                
                # Try dateutil parser first (most flexible)
                try:
                    parsed_dt = dateutil_parser.parse(date_str)
                    if parsed_dt.tzinfo is None:
                        parsed_dt = parsed_dt.replace(tzinfo=target_tz)
                    else:
                        parsed_dt = parsed_dt.astimezone(target_tz)
                    return parsed_dt
                except (ValueError, TypeError) as e:
                    # Fall back to manual format parsing
                    for fmt in self.COMMON_FORMATS:
                        try:
                            parsed_dt = datetime.strptime(date_str, fmt)
                            if parsed_dt.tzinfo is None:
                                parsed_dt = parsed_dt.replace(tzinfo=target_tz)
                            return parsed_dt
                        except ValueError:
                            continue
                    
                    # If all parsing attempts fail
                    raise DateParseError(f"Unable to parse date string: '{date_str}'") from e
            
            # Unsupported type
            raise DateParseError(f"Unsupported date input type: {type(date_input)}")
            
        except DateParseError:
            if strict:
                raise
            return self.now(timezone_input)
        except Exception as e:
            error_msg = f"Unexpected error parsing date '{date_input}': {str(e)}"
            if strict:
                raise DateParseError(error_msg) from e
            return self.now(timezone_input)
    
    def now(self, timezone_input: TimezoneInput = None) -> datetime:
        """
        Get current datetime in specified timezone.
        
        Args:
            timezone_input: Target timezone (default timezone if None)
            
        Returns:
            Current datetime in specified timezone
        """
        target_tz = self._normalize_timezone(timezone_input or self.default_timezone)
        return datetime.now(target_tz)
    
    def utc_now(self) -> datetime:
        """
        Get current UTC datetime.
        
        Returns:
            Current UTC datetime
        """
        return datetime.now(timezone.utc)
    
    def to_iso(self, dt: DateTimeInput, include_microseconds: bool = False,
               timezone_input: TimezoneInput = None) -> str:
        """
        Format datetime as ISO 8601 string for API compatibility.
        
        Args:
            dt: Datetime input to format
            include_microseconds: Whether to include microseconds
            timezone_input: Target timezone (UTC if None)
            
        Returns:
            ISO 8601 formatted string
        """
        parsed_dt = self.parse(dt, timezone_input or timezone.utc)
        
        if include_microseconds:
            return parsed_dt.strftime(self.ISO_8601_WITH_MS_FORMAT)
        else:
            return parsed_dt.strftime(self.ISO_8601_FORMAT)
    
    def to_local_iso(self, dt: DateTimeInput, include_microseconds: bool = False) -> str:
        """
        Format datetime as local ISO 8601 string (without timezone indicator).
        
        Args:
            dt: Datetime input to format
            include_microseconds: Whether to include microseconds
            
        Returns:
            Local ISO 8601 formatted string
        """
        parsed_dt = self.parse(dt)
        
        if include_microseconds:
            return parsed_dt.strftime('%Y-%m-%dT%H:%M:%S.%f')
        else:
            return parsed_dt.strftime(self.ISO_8601_LOCAL_FORMAT)
    
    def format(self, dt: DateTimeInput, format_str: str, 
               timezone_input: TimezoneInput = None) -> str:
        """
        Format datetime using custom format string.
        
        Args:
            dt: Datetime input to format
            format_str: Python datetime format string
            timezone_input: Target timezone
            
        Returns:
            Formatted datetime string
        """
        parsed_dt = self.parse(dt, timezone_input)
        return parsed_dt.strftime(format_str)
    
    def to_timestamp(self, dt: DateTimeInput, milliseconds: bool = False) -> int:
        """
        Convert datetime to Unix timestamp.
        
        Args:
            dt: Datetime input to convert
            milliseconds: If True, return milliseconds timestamp
            
        Returns:
            Unix timestamp (seconds or milliseconds)
        """
        parsed_dt = self.parse(dt)
        timestamp = int(parsed_dt.timestamp())
        
        if milliseconds:
            timestamp *= 1000
            
        return timestamp
    
    def add_time(self, dt: DateTimeInput, **kwargs) -> datetime:
        """
        Add time duration to datetime using relativedelta for accurate calculations.
        
        Args:
            dt: Base datetime
            **kwargs: Time components (years, months, weeks, days, hours, minutes, seconds, microseconds)
            
        Returns:
            Modified datetime
        """
        parsed_dt = self.parse(dt)
        
        # Separate relativedelta and timedelta arguments
        relativedelta_args = {}
        timedelta_args = {}
        
        for key, value in kwargs.items():
            if key in ['years', 'months']:
                relativedelta_args[key] = value
            elif key in ['weeks', 'days', 'hours', 'minutes', 'seconds', 'microseconds']:
                timedelta_args[key] = value
            else:
                raise ValueError(f"Unsupported time component: {key}")
        
        # Apply relativedelta for months/years (handles month-end dates correctly)
        if relativedelta_args:
            parsed_dt = parsed_dt + relativedelta(**relativedelta_args)
        
        # Apply timedelta for other components
        if timedelta_args:
            parsed_dt = parsed_dt + timedelta(**timedelta_args)
        
        return parsed_dt
    
    def subtract_time(self, dt: DateTimeInput, **kwargs) -> datetime:
        """
        Subtract time duration from datetime.
        
        Args:
            dt: Base datetime
            **kwargs: Time components to subtract
            
        Returns:
            Modified datetime
        """
        # Negate all values and use add_time
        negated_kwargs = {key: -value for key, value in kwargs.items()}
        return self.add_time(dt, **negated_kwargs)
    
    def diff(self, dt1: DateTimeInput, dt2: DateTimeInput, unit: str = 'seconds') -> float:
        """
        Calculate difference between two datetimes.
        
        Args:
            dt1: First datetime
            dt2: Second datetime
            unit: Unit for difference ('years', 'months', 'weeks', 'days', 'hours', 'minutes', 'seconds')
            
        Returns:
            Difference in specified unit
        """
        parsed_dt1 = self.parse(dt1)
        parsed_dt2 = self.parse(dt2)
        
        delta = parsed_dt1 - parsed_dt2
        
        if unit == 'seconds':
            return delta.total_seconds()
        elif unit == 'minutes':
            return delta.total_seconds() / 60
        elif unit == 'hours':
            return delta.total_seconds() / 3600
        elif unit == 'days':
            return delta.days + (delta.seconds / 86400)
        elif unit == 'weeks':
            return delta.days / 7
        elif unit == 'months':
            # Approximate calculation for months
            return (delta.days / 30.44)  # Average days per month
        elif unit == 'years':
            # Approximate calculation for years
            return (delta.days / 365.25)  # Average days per year
        else:
            raise ValueError(f"Unsupported unit: {unit}")
    
    def is_before(self, dt1: DateTimeInput, dt2: DateTimeInput) -> bool:
        """Check if dt1 is before dt2."""
        return self.parse(dt1) < self.parse(dt2)
    
    def is_after(self, dt1: DateTimeInput, dt2: DateTimeInput) -> bool:
        """Check if dt1 is after dt2."""
        return self.parse(dt1) > self.parse(dt2)
    
    def is_same(self, dt1: DateTimeInput, dt2: DateTimeInput, granularity: str = 'second') -> bool:
        """
        Check if two datetimes are the same at specified granularity.
        
        Args:
            dt1: First datetime
            dt2: Second datetime
            granularity: Comparison granularity ('year', 'month', 'day', 'hour', 'minute', 'second')
            
        Returns:
            True if datetimes are same at specified granularity
        """
        parsed_dt1 = self.parse(dt1)
        parsed_dt2 = self.parse(dt2)
        
        if granularity == 'year':
            return parsed_dt1.year == parsed_dt2.year
        elif granularity == 'month':
            return (parsed_dt1.year == parsed_dt2.year and 
                   parsed_dt1.month == parsed_dt2.month)
        elif granularity == 'day':
            return parsed_dt1.date() == parsed_dt2.date()
        elif granularity == 'hour':
            return (parsed_dt1.date() == parsed_dt2.date() and 
                   parsed_dt1.hour == parsed_dt2.hour)
        elif granularity == 'minute':
            return (parsed_dt1.date() == parsed_dt2.date() and 
                   parsed_dt1.hour == parsed_dt2.hour and 
                   parsed_dt1.minute == parsed_dt2.minute)
        elif granularity == 'second':
            return (parsed_dt1.date() == parsed_dt2.date() and 
                   parsed_dt1.hour == parsed_dt2.hour and 
                   parsed_dt1.minute == parsed_dt2.minute and 
                   parsed_dt1.second == parsed_dt2.second)
        else:
            raise ValueError(f"Unsupported granularity: {granularity}")
    
    def start_of(self, dt: DateTimeInput, unit: str) -> datetime:
        """
        Get the start of specified time unit.
        
        Args:
            dt: Input datetime
            unit: Time unit ('year', 'month', 'week', 'day', 'hour', 'minute', 'second')
            
        Returns:
            Datetime at the start of specified unit
        """
        parsed_dt = self.parse(dt)
        
        if unit == 'year':
            return parsed_dt.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        elif unit == 'month':
            return parsed_dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        elif unit == 'week':
            # Start of week (Monday)
            days_since_monday = parsed_dt.weekday()
            start_of_week = parsed_dt - timedelta(days=days_since_monday)
            return start_of_week.replace(hour=0, minute=0, second=0, microsecond=0)
        elif unit == 'day':
            return parsed_dt.replace(hour=0, minute=0, second=0, microsecond=0)
        elif unit == 'hour':
            return parsed_dt.replace(minute=0, second=0, microsecond=0)
        elif unit == 'minute':
            return parsed_dt.replace(second=0, microsecond=0)
        elif unit == 'second':
            return parsed_dt.replace(microsecond=0)
        else:
            raise ValueError(f"Unsupported unit: {unit}")
    
    def end_of(self, dt: DateTimeInput, unit: str) -> datetime:
        """
        Get the end of specified time unit.
        
        Args:
            dt: Input datetime
            unit: Time unit ('year', 'month', 'week', 'day', 'hour', 'minute', 'second')
            
        Returns:
            Datetime at the end of specified unit
        """
        parsed_dt = self.parse(dt)
        
        if unit == 'year':
            return parsed_dt.replace(month=12, day=31, hour=23, minute=59, second=59, microsecond=999999)
        elif unit == 'month':
            # Last day of month
            next_month = parsed_dt.replace(day=28) + timedelta(days=4)
            last_day = next_month - timedelta(days=next_month.day)
            return last_day.replace(hour=23, minute=59, second=59, microsecond=999999)
        elif unit == 'week':
            # End of week (Sunday)
            days_until_sunday = 6 - parsed_dt.weekday()
            end_of_week = parsed_dt + timedelta(days=days_until_sunday)
            return end_of_week.replace(hour=23, minute=59, second=59, microsecond=999999)
        elif unit == 'day':
            return parsed_dt.replace(hour=23, minute=59, second=59, microsecond=999999)
        elif unit == 'hour':
            return parsed_dt.replace(minute=59, second=59, microsecond=999999)
        elif unit == 'minute':
            return parsed_dt.replace(second=59, microsecond=999999)
        elif unit == 'second':
            return parsed_dt.replace(microsecond=999999)
        else:
            raise ValueError(f"Unsupported unit: {unit}")


# Global instance for convenient access
_default_processor = DateTimeProcessor()

# Convenience functions that use the default processor
def parse(date_input: DateTimeInput, timezone_input: TimezoneInput = None, 
          strict: bool = False) -> datetime:
    """Parse date input using default processor."""
    return _default_processor.parse(date_input, timezone_input, strict)


def now(timezone_input: TimezoneInput = None) -> datetime:
    """Get current datetime using default processor."""
    return _default_processor.now(timezone_input)


def utc_now() -> datetime:
    """Get current UTC datetime using default processor."""
    return _default_processor.utc_now()


def to_iso(dt: DateTimeInput, include_microseconds: bool = False,
           timezone_input: TimezoneInput = None) -> str:
    """Format datetime as ISO 8601 string using default processor."""
    return _default_processor.to_iso(dt, include_microseconds, timezone_input)


def to_local_iso(dt: DateTimeInput, include_microseconds: bool = False) -> str:
    """Format datetime as local ISO 8601 string using default processor."""
    return _default_processor.to_local_iso(dt, include_microseconds)


def format_datetime(dt: DateTimeInput, format_str: str, 
                   timezone_input: TimezoneInput = None) -> str:
    """Format datetime using custom format string using default processor."""
    return _default_processor.format(dt, format_str, timezone_input)


def to_timestamp(dt: DateTimeInput, milliseconds: bool = False) -> int:
    """Convert datetime to Unix timestamp using default processor."""
    return _default_processor.to_timestamp(dt, milliseconds)


def add_time(dt: DateTimeInput, **kwargs) -> datetime:
    """Add time duration to datetime using default processor."""
    return _default_processor.add_time(dt, **kwargs)


def subtract_time(dt: DateTimeInput, **kwargs) -> datetime:
    """Subtract time duration from datetime using default processor."""
    return _default_processor.subtract_time(dt, **kwargs)


def diff(dt1: DateTimeInput, dt2: DateTimeInput, unit: str = 'seconds') -> float:
    """Calculate difference between two datetimes using default processor."""
    return _default_processor.diff(dt1, dt2, unit)


def is_valid_date(date_input: Any) -> bool:
    """
    Validate if input can be parsed as a valid date.
    
    Args:
        date_input: Input to validate
        
    Returns:
        True if input is a valid date, False otherwise
    """
    try:
        _default_processor.parse(date_input, strict=True)
        return True
    except (DateParseError, DateTimeError):
        return False


def validate_date_range(start_date: DateTimeInput, end_date: DateTimeInput, 
                       allow_same: bool = True) -> bool:
    """
    Validate that start_date is before or equal to end_date.
    
    Args:
        start_date: Start date to validate
        end_date: End date to validate
        allow_same: Whether to allow start_date == end_date
        
    Returns:
        True if date range is valid, False otherwise
    """
    try:
        parsed_start = _default_processor.parse(start_date, strict=True)
        parsed_end = _default_processor.parse(end_date, strict=True)
        
        if allow_same:
            return parsed_start <= parsed_end
        else:
            return parsed_start < parsed_end
    except (DateParseError, DateTimeError):
        return False


def get_business_days(start_date: DateTimeInput, end_date: DateTimeInput, 
                     exclude_weekends: bool = True) -> int:
    """
    Calculate the number of business days between two dates.
    
    Args:
        start_date: Start date
        end_date: End date
        exclude_weekends: Whether to exclude weekends (Saturday, Sunday)
        
    Returns:
        Number of business days
    """
    parsed_start = _default_processor.parse(start_date).date()
    parsed_end = _default_processor.parse(end_date).date()
    
    if parsed_start > parsed_end:
        parsed_start, parsed_end = parsed_end, parsed_start
    
    business_days = 0
    current_date = parsed_start
    
    while current_date <= parsed_end:
        if not exclude_weekends or current_date.weekday() < 5:  # 0-6, Monday is 0
            business_days += 1
        current_date += timedelta(days=1)
    
    return business_days


def get_quarter(dt: DateTimeInput) -> int:
    """
    Get the quarter (1-4) for the given date.
    
    Args:
        dt: Input date
        
    Returns:
        Quarter number (1-4)
    """
    parsed_dt = _default_processor.parse(dt)
    return (parsed_dt.month - 1) // 3 + 1


def get_week_of_year(dt: DateTimeInput) -> int:
    """
    Get the week number of the year for the given date.
    
    Args:
        dt: Input date
        
    Returns:
        Week number (1-53)
    """
    parsed_dt = _default_processor.parse(dt)
    return parsed_dt.isocalendar()[1]


def is_leap_year(year_or_date: Union[int, DateTimeInput]) -> bool:
    """
    Check if the given year is a leap year.
    
    Args:
        year_or_date: Year as integer or date input
        
    Returns:
        True if leap year, False otherwise
    """
    if isinstance(year_or_date, int):
        year = year_or_date
    else:
        year = _default_processor.parse(year_or_date).year
    
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def get_days_in_month(year_or_date: Union[int, DateTimeInput], month: Optional[int] = None) -> int:
    """
    Get the number of days in the specified month.
    
    Args:
        year_or_date: Year as integer or date input
        month: Month number (1-12), required if year_or_date is int
        
    Returns:
        Number of days in the month
    """
    if isinstance(year_or_date, int):
        if month is None:
            raise ValueError("Month is required when providing year as integer")
        year = year_or_date
        month_num = month
    else:
        parsed_dt = _default_processor.parse(year_or_date)
        year = parsed_dt.year
        month_num = parsed_dt.month
    
    # Use the next month's first day minus one day to get last day of current month
    if month_num == 12:
        next_month = datetime(year + 1, 1, 1)
    else:
        next_month = datetime(year, month_num + 1, 1)
    
    last_day = next_month - timedelta(days=1)
    return last_day.day


def create_date_range(start_date: DateTimeInput, end_date: DateTimeInput, 
                     step_days: int = 1) -> List[datetime]:
    """
    Create a list of dates between start_date and end_date.
    
    Args:
        start_date: Start date
        end_date: End date
        step_days: Number of days between each date
        
    Returns:
        List of datetime objects
    """
    parsed_start = _default_processor.parse(start_date)
    parsed_end = _default_processor.parse(end_date)
    
    if step_days <= 0:
        raise ValueError("step_days must be positive")
    
    dates = []
    current_date = parsed_start
    
    while current_date <= parsed_end:
        dates.append(current_date)
        current_date += timedelta(days=step_days)
    
    return dates


# Timezone utilities
def get_available_timezones() -> List[str]:
    """
    Get list of available timezone names.
    
    Returns:
        List of timezone names
    """
    import zoneinfo
    try:
        return sorted(zoneinfo.available_timezones())
    except AttributeError:
        # Fallback for Python < 3.9
        import pytz
        return sorted(pytz.all_timezones)


def convert_timezone(dt: DateTimeInput, from_tz: TimezoneInput, 
                    to_tz: TimezoneInput) -> datetime:
    """
    Convert datetime from one timezone to another.
    
    Args:
        dt: Input datetime
        from_tz: Source timezone
        to_tz: Target timezone
        
    Returns:
        Datetime in target timezone
    """
    processor = DateTimeProcessor(from_tz)
    parsed_dt = processor.parse(dt)
    target_tz = processor._normalize_timezone(to_tz)
    return parsed_dt.astimezone(target_tz)


# Business logic utilities
def get_age(birth_date: DateTimeInput, reference_date: Optional[DateTimeInput] = None) -> int:
    """
    Calculate age in years from birth date.
    
    Args:
        birth_date: Birth date
        reference_date: Reference date for age calculation (current date if None)
        
    Returns:
        Age in years
    """
    parsed_birth = _default_processor.parse(birth_date)
    parsed_ref = _default_processor.parse(reference_date) if reference_date else _default_processor.now()
    
    age = parsed_ref.year - parsed_birth.year
    
    # Adjust if birthday hasn't occurred this year
    if (parsed_ref.month, parsed_ref.day) < (parsed_birth.month, parsed_birth.day):
        age -= 1
    
    return age


def is_business_hour(dt: DateTimeInput, start_hour: int = 9, end_hour: int = 17, 
                    exclude_weekends: bool = True) -> bool:
    """
    Check if datetime falls within business hours.
    
    Args:
        dt: Input datetime
        start_hour: Business start hour (24-hour format)
        end_hour: Business end hour (24-hour format)
        exclude_weekends: Whether to exclude weekends
        
    Returns:
        True if within business hours, False otherwise
    """
    parsed_dt = _default_processor.parse(dt)
    
    # Check weekend
    if exclude_weekends and parsed_dt.weekday() >= 5:  # Saturday=5, Sunday=6
        return False
    
    # Check hours
    return start_hour <= parsed_dt.hour < end_hour


def format_duration(seconds: Union[int, float], include_microseconds: bool = False) -> str:
    """
    Format duration in seconds as human-readable string.
    
    Args:
        seconds: Duration in seconds
        include_microseconds: Whether to include microseconds
        
    Returns:
        Formatted duration string
    """
    if seconds < 0:
        negative = True
        seconds = abs(seconds)
    else:
        negative = False
    
    hours, remainder = divmod(int(seconds), 3600)
    minutes, secs = divmod(remainder, 60)
    
    parts = []
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if secs > 0 or not parts:
        if include_microseconds:
            microseconds = int((seconds - int(seconds)) * 1000000)
            if microseconds > 0:
                parts.append(f"{secs}.{microseconds:06d}s")
            else:
                parts.append(f"{secs}s")
        else:
            parts.append(f"{secs}s")
    
    result = " ".join(parts)
    return f"-{result}" if negative else result


# Export the main processor class and key functions
__all__ = [
    'DateTimeProcessor',
    'DateTimeError',
    'DateParseError', 
    'TimezoneError',
    'DateValidationError',
    'parse',
    'now',
    'utc_now',
    'to_iso',
    'to_local_iso',
    'format_datetime',
    'to_timestamp',
    'add_time',
    'subtract_time',
    'diff',
    'is_valid_date',
    'validate_date_range',
    'get_business_days',
    'get_quarter',
    'get_week_of_year',
    'is_leap_year',
    'get_days_in_month',
    'create_date_range',
    'get_available_timezones',
    'convert_timezone',
    'get_age',
    'is_business_hour',
    'format_duration',
]