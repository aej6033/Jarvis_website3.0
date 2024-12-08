//
//  OnboardingView.swift
//  SteadyFit
//
//  Created by Debbie Shih on 11/20/24.
//

import SwiftUI

class FitnessSurveyData: ObservableObject {
    @Published var physicalActivityPerWeek: String = "Choose frequency"
    @Published var workRelatedActivity: String = "Choose option"
    @Published var transportationRelatedActivity: String = "Choose option"
    @Published var recreationalRelatedActivity: String = "Choose frequency"
    @Published var sedentaryRelatedActivity: String = "Choose hours"
    @Published var physicalActivityIntensity: String = "Choose intensity"
    
}

struct OnboardingTitleView: View {
    var body: some View {
        NavigationView {
            VStack {
                HeaderView()
                VStack(alignment: .center) {
                        Text("Welcome to SteadyFit!")
                            .font(.custom("Poppins-Bold", size: 30))
                            .multilineTextAlignment(.leading)
                            .padding(.top, 80)
                        Text("To help us create a personalized experience just for you, we’ll start with a quick survey about your fitness level.")
                        .font(.custom("Poppins", size: 20))
                        .padding(.top, 20.0)
                    
                    }
                    Spacer()
                HStack {
                    NavigationLink(destination: OnboardingSurveyView()) {
                        Text("Next")
                            .fontWeight(.medium)
                            .foregroundColor(.white)
                        Spacer()
                        Image(systemName: "arrow.right")
                            .resizable()
                            .frame(width: 25, height: 25)
                            .foregroundColor(.white)
                            .padding()
                    }
                }
                    .padding(40)
                    .frame(width: 410, height: 80)
                    .background(Color.deepBlue)
                }
                .frame(width: 350)
                .ignoresSafeArea()
            }
        .navigationBarBackButtonHidden(true)
    }
}

struct OnboardingSurveyView: View {
    @StateObject var fitnessSurveyData = FitnessSurveyData()
    let physicalActivityPerWeekOptions = ["Choose frequency", "0 days", "1-2 days", "3-4 days", "5-6 days", "7 days"]
    let workRelatedActivityOptions = ["Choose option", "Yes, mostly sedentary with little physical activity", "Yes, moderately active (some walking or standing)", "Yes, very active (heavy physical labor)", "No"]
    let transportationRelatedActivityOptions = ["Choose option", "Mostly by car or public transportation", "Often walk or bike", "Mix of walking/biking and car/public transportation"]
    let sedentaryRelatedActivityOptions = ["Choose hours", "Less than 2 hours", "2-4 hours", "4-6 hours", "6-8 hours", "More than 8 hours"]
    let physicalActivityIntensityOptions = ["Choose intensity", "Mostly light (e.g., walking at a casual pace)", "Mostly moderate (e.g., brisk walking, biking)", "Mostly vigorous (e.g., running, heavy lifting)", "N/a"]
    var body: some View {
        ZStack { // Wrap in ZStack to detect taps outside of text fields
            VStack {
                HeaderView()
                ScrollView {
                    VStack(alignment: .leading) {
                        Text("Fitness Level Survey")
                            .font(.custom("Poppins-Bold", size: 30))
                            .padding(.bottom, 20)
                        
                        Text("How many days per week do you engage in physical activity for at least 30 minutes?")
                            .font(.custom("Poppins", size: 20))
                        DropdownPicker(selection: $fitnessSurveyData.physicalActivityPerWeek, options: physicalActivityPerWeekOptions)
                        
                        Text("Does your job require you to be physically active (e.g., walking, standing, lifting)?")
                            .font(.custom("Poppins", size: 20))
                        DropdownPicker(selection: $fitnessSurveyData.workRelatedActivity, options: workRelatedActivityOptions)
                        
                        Text("How do you usually travel to and from work or school?")
                            .font(.custom("Poppins", size: 20))
                        DropdownPicker(selection: $fitnessSurveyData.transportationRelatedActivity, options: transportationRelatedActivityOptions)
                        
                        Text("How many days per week do you engage in recreational physical activities (e.g., sports, exercise, gardening)?")
                            .font(.custom("Poppins", size: 20))
                        DropdownPicker(selection: $fitnessSurveyData.recreationalRelatedActivity, options: physicalActivityPerWeekOptions)
                        
                        Text("On average, how many hours per day do you spend sitting (e.g., working, watching TV, using a computer)?")
                            .font(.custom("Poppins", size: 20))
                        DropdownPicker(selection: $fitnessSurveyData.sedentaryRelatedActivity, options: sedentaryRelatedActivityOptions)
                        Text("When you engage in physical activity, how would you describe the intensity?")
                            .font(.custom("Poppins", size: 20))
                        DropdownPicker(selection: $fitnessSurveyData.physicalActivityIntensity, options: physicalActivityIntensityOptions)
                    }
                }
                .padding(.top, 20)
                Spacer()
                
                VStack(spacing: 0) {
                    HStack {
                        HStack {
                            Button(action: {
                                GamesStore.shared.postFitnessSurvey(fitnessSurveyData)
                                // navigateToHome = true
                                // Trigger navigation
                            }) {
                                HStack {
                                    Text("Publish")
                                        .fontWeight(.medium)
                                        .foregroundColor(.white)
                                    Spacer()
                                    Image(systemName: "arrow.right")
                                        .resizable()
                                        .frame(width: 25, height: 25)
                                        .foregroundColor(.white)
                                        .padding()
                                }
                            }
                        }
                            .padding(40)
                            .frame(width: 410, height: 80)
                            .background(Color.deepBlue)
                    }
                    .padding(20)
                    .frame(width: 400, height: 80)
                    .background(Color.deepBlue)
                    NavBarView(viewIndex: 1)
                }
            }
            .frame(width: 350)
            .ignoresSafeArea()
        }
        .contentShape(Rectangle())
        .onTapGesture {
            hideKeyboard()
        }
        .navigationBarBackButtonHidden(true)
    }
}

#Preview {
    OnboardingSurveyView()
}
