using System;
using System.Collections.Generic;

namespace BookWorms.Services
{
    public class ExponentialBackoffService
    {
        private static readonly Dictionary<string, int> RequestCounts = new();
        private static readonly object LockObject = new();
        private readonly int _initialDelayInSeconds;

        public ExponentialBackoffService(int initialDelayInSeconds)
        {
            _initialDelayInSeconds = initialDelayInSeconds;
        }

        public int GetDelay(string key)
        {
            lock (LockObject)
            {
                if (!RequestCounts.ContainsKey(key))
                {
                    RequestCounts[key] = 0;
                }
                var count = RequestCounts[key];
                RequestCounts[key]++;
                return (int)Math.Pow(2, count) * _initialDelayInSeconds;
            }
        }

        public void Reset(string key)
        {
            lock (LockObject)
            {
                if (RequestCounts.ContainsKey(key))
                {
                    RequestCounts[key] = 0;
                }
            }
        }
    }
}
