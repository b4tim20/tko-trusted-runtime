export default function LicenseRequestForm() {
  return (
    <form className="bg-gray-900 text-white p-6 rounded-md w-full max-w-md mx-auto mt-12 shadow-md">
      <h2 className="text-xl font-bold mb-4">Request Commercial License</h2>
      <input
        type="email"
        placeholder="Your Email"
        className="w-full p-2 mb-4 bg-black border border-green-400 rounded"
      />
      <textarea
        placeholder="Company, Use Case, Questions"
        className="w-full p-2 mb-4 bg-black border border-green-400 rounded"
        rows={4}
      />
      <button
        type="submit"
        className="bg-green-500 text-black px-4 py-2 rounded font-semibold hover:bg-green-400"
      >
        Submit
      </button>
    </form>
  );
}