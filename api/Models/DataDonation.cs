using System;

namespace DataDonation.Models
{
    public class DataDonationEntry
    {
        public DataDonationEntry(Guid id, DateTime date, string data)
        {
            Id = id;
            this.date = date;
            this.data = data;
        }

        public Guid Id { get; set; }
        public DateTime date { get; set; }
        public string data { get; set; }
    }
}