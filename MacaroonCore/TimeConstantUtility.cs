namespace MacaroonCore
{
    public static class TimeConstantUtility
    {
        public static bool TimeConstantCompare(this byte[] left, byte[] right)
        {
            // We currently leak the size of the correct size. But that is not a secret in any protocol that i know of. 
            if (left.Length != right.Length) return false;

            // If arrays are equal, we can XOR each byte and OR it to a zero byte. Then it should be zero at the end.
            // If not, at least one of the bytes were not equal, so we OR something non-zero onto the zero byte.

            // We will always do the same work, so constant time.
            // I.e. length * (XOR and OR) + 1 byte comparison at the end.

            byte mask = byte.MinValue;

            for (int i = 0; i < left.Length; i++)
            {
                byte temp = left[i];
                temp ^= right[i];
                mask |= temp;
            }

            return mask == byte.MinValue;
        }
    }
}
