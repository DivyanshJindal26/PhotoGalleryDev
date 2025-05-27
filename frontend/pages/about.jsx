import React from "react";

const About = () => {
  return (
    <div style={{ padding: "20px", maxWidth: "800px", margin: "0 auto", textAlign: "center" }}>
      <h1>About Us</h1>
      
      <div style={{ textAlign: "left", marginTop: "20px" }}>
        <h2>Developer</h2>
        <p><strong>Divyansh Jindal</strong></p>
        <p>Email: <a href="mailto:b24121@students.iitmandi.ac.in">b24121@students.iitmandi.ac.in</a></p>
        <p>Phone: +91 76260 40100</p>
      </div>

      <div style={{ textAlign: "left", marginTop: "20px" }}>
        <h2>Technical Secretary</h2>
        <p><strong>Vaibhav Kesharwani</strong></p>
        <p>Email: <a href="mailto:technical_secretary@students.iitmandi.ac.in">technical_secretary@students.iitmandi.ac.in</a></p>
        <p>Phone: +91 93690 80567</p>
      </div>

      <div style={{ marginTop: "30px" }}>
        <h2>Our Location</h2>
        <iframe
          title="IIT Mandi Location"
          width="100%"
          height="300"
          style={{ border: "0", borderRadius: "8px" }}
          allowFullScreen
          loading="lazy"
          referrerPolicy="no-referrer-when-downgrade"
          src="https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d3391.5589766691!2d76.99657057642452!3d31.782512574095023!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x3904e5ca553f4a27%3A0xe0c4d446cc9584ca!2sIIT%20Mandi!5e0!3m2!1sen!2sin!4v1739101004547!5m2!1sen!2sin"
        ></iframe>
      </div>

      <div style={{ marginTop: "20px", fontSize: "1em", opacity: 0.9 }}>
        <h2 style={{ fontSize: "1.1em", fontWeight: "500", marginBottom: "5px", }}>
          Contributors
        </h2>
        <p style={{ margin: "0", fontSize: "0.85em", lineHeight: "1.4" }}>
          <span style={{ fontWeight: "600" }}>Dhairya Sharma</span> - 
          <a href="mailto:b24241@students.iitmandi.ac.in"> b24241@students.iitmandi.ac.in</a>
          <br />
          <span style={{ fontWeight: "600" }}>Ojasvi Jain</span> - 
          <a href="mailto:b24208@students.iitmandi.ac.in"> b24208@students.iitmandi.ac.in</a>
        </p>
      </div>
    </div>
  );
};

export default About;